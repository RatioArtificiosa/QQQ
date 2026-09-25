// SPDX-License-Identifier: Apache-2.0

//! The fifteen-step request lifecycle, instrumented and **measured** — `ARCH-011`.
//!
//! # What the item asks, and what §4.4 says
//!
//! > **ARCH-011** Implement the fifteen-step request lifecycle as an instrumented
//! > pipeline.
//!
//! §4.4 calls its diagram *"the single most important diagram in this document.
//! Every design constraint elsewhere is visible here."* It names fifteen steps from
//! `LISTENER SHARD` to `AUDIT APPEND`.
//!
//! # Why this module reports status rather than asserting completion
//!
//! The first version of this module was going to state that the pipeline is
//! implemented. Auditing each step against the tree, one at a time, showed that
//! would have been false for **13** of the fifteen, so the table reports a
//! [`Status`] per step instead of a verdict. The numeral is deliberate: a number
//! written as a word cannot be compared to anything without a number-word parser,
//! and a value that cannot be compared is a value with no owner (`§O-277`).
//!
//! **The four counts below are derived, never hand-written.** [`Summary::of`] folds
//! [`STAGES`] into them, [`Summary::Display`] renders them, and
//! `the_documented_counts_match_the_table` compares the prose against that
//! rendering — which is **2 implemented, 11 partial, 1 built-unwired, 1 absent**.
//! A previous version of this module hand-wrote the same four numbers in three
//! places, and they disagreed: the table below said steps 2, 6, 8, 10, 14 were
//! implemented, the checklist entry said `5 implemented, 9 partial, 1 built-unwired,
//! 1 absent`, and `STAGES` held three implemented rows. The fix is the single
//! counting site, not three corrected numbers — `§O-244`.
//!
//! | Kind | Steps | What is actually true |
//! |---|---|---|
//! | **Implemented** | 2, 8 | The named symbol performs the step |
//! | **Partial** | 1, 3, 5, 6, 7, 9, 10, 11, 12, 13, 14 | Something performs the step, but not the whole of what §4.4 describes |
//! | **Built, unwired** | 15 | A complete implementation with no production caller |
//! | **Absent** | 4 | No implementation exists |
//!
//! A module that said "implemented" would be `§O-219`'s shape — an item that looks
//! done. So [`STAGES`] carries a [`Status`] per step, and [`audit`] verifies a
//! different, checkable property: **every symbol the table names still exists in
//! the file it names.** That is the property a later edit can break, and it is the
//! one an omission cannot hide from.
//!
//! # The five honest gaps, named
//!
//! These are the findings, and each is a decision or a debt rather than an
//! oversight:
//!
//! 1. **Step 4, `TENANT RESOLVE` — absent.** §4.4 maps *host/path → tenant →
//!    component ID + manifest rev*. There is no such mapping. The router
//!    ([`crate::route`]) is **path-only**: [`Route`] has no host field, and the
//!    only tenant derivation in this crate is
//!    [`tenant_of`](crate::server), which keys on the *client IP* for per-tenant
//!    limits. §4.4's claim that "step 4 is the only place routing state lives"
//!    therefore describes an intent, not the code.
//! 2. **Step 15, `AUDIT APPEND` — built, unwired.**
//!    [`AuditStream::record`](qqq_host::AuditStream::record) is a complete,
//!    hash-chained, append-only implementation whose only callers are its own
//!    tests. No request path constructs an audit stream, so no capability-use
//!    record reaches any ring.
//! 3. **Step 11, the call-time re-check — implemented per-function, unwired for the
//!    unbound interfaces.** [`recheck`](qqq_host::linker::recheck) exists, is
//!    tested, and is reached through `ambient::require` for the interface that
//!    needs it. `build_linker`'s own comment records that the interfaces which
//!    would call it most — `qqq:fs`, `qqq:sql` and the rest — are the ones not yet
//!    bound.
//! 4. **Steps 6 and 14 are accounting, not reuse.** §4.4 says step 6 takes "a
//!    pooled instance (≈µs)", and step 14's payoff is that "a pooled instance's
//!    linear memory is reset, not freed". In V1 nothing reuses an instance:
//!    [`Pool::acquire`](qqq_host::Pool::acquire) charges a slot and
//!    [`Pool::release`](qqq_host::Pool::release) returns it, while the instance
//!    itself is created and dropped per request. `Acquired::pooled` means the idle
//!    count was non-zero — not that a guest instance was reused.
//! 5. **Step 10, `GUEST ENTRY` — the production path is synchronous where §4.4 says
//!    async.** [`call_handler`](qqq_host::call::call_handler) resolves the handler
//!    once per component and calls it, and the async machinery exists in full —
//!    but the dispatch path the server actually takes uses the synchronous entry
//!    points. This row read `Implemented` with an empty `gap` while the comment
//!    above it recorded the deviation, which is the shape `§O-219` names: the step
//!    looked finished because the thing that would notice was the thing describing
//!    it. CodeRabbit raised it twice. It is `Partial` now, and the Status, the gap
//!    and this list agree (`§O-277`).
//!
//! # Instrumentation
//!
//! "Instrumented" is the other half of the item, and it is real even where the
//! pipeline is incomplete: [`crate::metrics::HttpMetrics::record_request`] records
//! wall time, bytes in and out, and connection counts;
//! [`qqq_host::Metrics::note_execution`] records fuel delta, traps and peak
//! memory. **They are two registries, not one**, and nothing joins them, so a
//! request's fuel cost and its latency are recorded in different places. §4.4's
//! step 13 — *"fuel delta, wall time, bytes, handle peak → telemetry"* — is
//! therefore three-quarters done: **no handle peak reaches telemetry on the HTTP
//! path**, and the two registries have no common key.
//!
//! One instrument *is* complete and worth naming, because it is what makes the
//! others checkable: `qqq-serve`'s per-connection trace id
//! ([`crate::conn`]) is allocated per connection and attached to every record for
//! requests on it, so records can be correlated without a global counter.

use std::fmt;

/// How completely one §4.4 step is implemented.
///
/// The variants are ordered by completeness, so `Status::Absent < Status::Partial
/// < Status::Implemented` and a summary can report the weakest step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Status {
    /// §4.4 describes the step and no code performs it.
    Absent,
    /// Some code performs the step, but not all of what §4.4 describes. The row's
    /// `gap` field says what is missing.
    Partial,
    /// A complete implementation exists and no production path calls it. This is
    /// its own variant because "the code is written" and "the pipeline runs it"
    /// are different facts, and conflating them is how an unwired feature reads as
    /// shippable.
    BuiltUnwired,
    /// The named symbol performs the step on the production path.
    Implemented,
}

impl Status {
    /// A short label for reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Partial => "partial",
            Self::BuiltUnwired => "built-unwired",
            Self::Implemented => "implemented",
        }
    }

    /// Whether the step is complete **and** reachable.
    #[must_use]
    pub const fn is_done(self) -> bool {
        matches!(self, Self::Implemented)
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One row of §4.4's diagram, with where it lives and how complete it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stage {
    /// The step's number in §4.4, 1-based.
    pub step: u8,
    /// The step's name, verbatim from §4.4's diagram.
    pub name: &'static str,
    /// The crate-relative path of the file the symbol lives in, for the steps that
    /// have one. `None` for a step with no implementation.
    pub file: Option<&'static str>,
    /// The primary symbol that performs the step. `None` when there is none.
    pub symbol: Option<&'static str>,
    /// How completely the step is implemented.
    pub status: Status,
    /// What is missing, for every row that is not [`Status::Implemented`]. Empty
    /// for rows that are.
    pub gap: &'static str,
}

/// §4.4's fifteen steps, each measured against the tree.
///
/// The `file` and `symbol` fields are verified by [`audit`]; the `status` and `gap`
/// fields are judgements that a human has to keep true, which is why [`audit`]
/// reports them rather than trusting them.
pub const STAGES: [Stage; 15] = [
    Stage {
        step: 1,
        name: "LISTENER SHARD",
        file: Some("qqq-io/src/listener.rs"),
        symbol: Some("accept_stream"),
        // The accept loop and the shard assignment both exist. §4.4's parenthetical
        // "same core" is the part that is not implemented: `qqq-io`'s shard module
        // argues explicitly for round-robin in userspace rather than affinity or
        // `SO_REUSEPORT`, on the grounds that it behaves identically on every
        // platform. So the step runs; the locality claim behind it does not.
        status: Status::Partial,
        gap: "sharding is round-robin in userspace; no same-core affinity is set",
    },
    Stage {
        step: 2,
        name: "HTTP PARSE",
        file: Some("qqq-serve/src/http1.rs"),
        symbol: Some("parse_head"),
        // Hand-written rather than hyper, and the module argues for that choice.
        // The body is deliberately left to the caller, so "body stays a stream"
        // holds at this step.
        status: Status::Implemented,
        gap: "",
    },
    Stage {
        step: 3,
        name: "ROUTE MATCH",
        file: Some("qqq-serve/src/route.rs"),
        symbol: Some("match_route"),
        // A segment trie over the path. Two deviations from §4.4, both measured:
        // the match is **path-only** (no host dimension), and "no allocation on
        // the hot path" is not true — the match collects segments into a `Vec`
        // and a capture becomes a `String` per request.
        status: Status::Partial,
        gap: "path-only (no host dimension); allocates a segment Vec and one String per capture",
    },
    Stage {
        step: 4,
        name: "TENANT RESOLVE",
        file: None,
        symbol: None,
        // The only tenant derivation in `qqq-serve` is `tenant_of`, keyed on the
        // client IP for per-tenant limits. There is no host/path -> tenant ->
        // component ID + manifest rev map anywhere in the workspace.
        status: Status::Absent,
        gap: "no host/path -> tenant -> component ID + manifest rev mapping exists; `tenant_of` keys on the client IP for limits only",
    },
    Stage {
        step: 5,
        name: "POLICY CHECK",
        file: Some("qqq-serve/src/auth.rs"),
        symbol: Some("decide"),
        // Fail-closed, which is the right default and is stated as such. But it
        // checks the *route's* declared auth mode and refuses every mode this
        // crate cannot verify; there is no principal, and no export-level check.
        status: Status::Partial,
        gap: "checks the route's declared auth mode, not a principal; export-level authorisation is not performed",
    },
    Stage {
        step: 6,
        name: "INSTANCE ACQUIRE",
        file: Some("qqq-host/src/pool.rs"),
        symbol: Some("acquire"),
        // The slot accounting and its backpressure are real. The reuse is not:
        // nothing in V1 takes a previously-used instance from the free list, so
        // the "≈µs" path does not exist yet.
        status: Status::Partial,
        gap: "charges a pool slot with backpressure; no instance is actually reused, so the pooled path does not exist",
    },
    Stage {
        step: 7,
        name: "CAPABILITY BIND",
        file: Some("qqq-host/src/linker.rs"),
        symbol: Some("build_linker"),
        // Building the linker from the grants alone is the security property and it
        // holds. The gap is coverage: only the clock, crypto and http interfaces
        // are registered so far, and the rest are reported as unimplemented.
        status: Status::Partial,
        gap: "only clock/crypto/http register; fs, sql and the rest are reported unimplemented rather than bound",
    },
    Stage {
        step: 8,
        name: "LIMIT BIND",
        file: Some("qqq-host/src/instance.rs"),
        symbol: Some("prepare"),
        // Memory via the trapping limiter, fuel, epoch deadline, handle and
        // subrequest quotas — all before instantiation, as the doc requires.
        status: Status::Implemented,
        gap: "",
    },
    Stage {
        step: 9,
        name: "REQUEST ADAPT",
        file: Some("qqq-run/src/guest_bridge.rs"),
        symbol: Some("request_from_head"),
        // Lowering to `wasi:http` types is real. "Body becomes a stream" is not:
        // the body is materialised into a `Vec<u8>` before the call, so a large
        // upload is fully buffered on the host.
        status: Status::Partial,
        gap: "the body is fully buffered into a Vec<u8>, not streamed into the guest",
    },
    Stage {
        step: 10,
        name: "GUEST ENTRY",
        file: Some("qqq-host/src/call.rs"),
        symbol: Some("call_handler"),
        // The handler is resolved once per component and called. §4.4 says the host
        // "runs it async"; the async machinery exists in full, but the production
        // dispatch path uses the synchronous entry points.
        //
        // **That is a deviation, so this step is `Partial` and not `Implemented`.**
        // Reporting it complete while the comment above records a gap is the shape
        // `§O-219` names: an item that looks finished because the thing that would
        // notice is the thing being described. CodeRabbit raised it twice before the
        // Status agreed with the prose.
        status: Status::Partial,
        gap: "production dispatch uses the synchronous entry points; §4.4 specifies async",
    },
    Stage {
        step: 11,
        name: "HOST CALLS",
        file: Some("qqq-host/src/linker.rs"),
        symbol: Some("recheck"),
        // The re-check exists and is reached for the interfaces that need it. The
        // unwired part is the interfaces that are not bound yet, which is where
        // most host calls will eventually come from.
        status: Status::Partial,
        gap: "recheck is reached through ambient::require, but the interfaces that would call it most (fs, sql) are not bound",
    },
    Stage {
        step: 12,
        name: "RESPONSE ADAPT",
        file: Some("qqq-run/src/guest_handler.rs"),
        symbol: Some("to_served"),
        // The conversion is real and carefully done — non-UTF-8 header values are
        // dropped rather than corrupted. The body is a buffered `Vec<u8>`, so
        // "streams pass through" is not true on the guest path.
        status: Status::Partial,
        gap: "the response body is fully buffered; no guest-path streaming",
    },
    Stage {
        step: 13,
        name: "METER + TRACE",
        file: Some("qqq-serve/src/metrics.rs"),
        symbol: Some("record_request"),
        // Latency, bytes and connection counts are recorded here; fuel delta and
        // peak memory in qqq-host's separate registry. Nothing joins them, and no
        // handle peak reaches telemetry.
        status: Status::Partial,
        gap: "two unjoined registries (serve + host); no handle peak reaches telemetry",
    },
    Stage {
        step: 14,
        name: "INSTANCE RELEASE",
        file: Some("qqq-host/src/pool.rs"),
        symbol: Some("release"),
        // The trap-discard distinction is real and enforced by ownership:
        // `release` is the only path back to the free list, `discard` never
        // returns. What does not exist is the reset §4.4 describes, because no
        // instance is reused, so there is no linear memory to reset.
        status: Status::Partial,
        gap: "slot accounting and trap-discard are real; there is no memory reset because no instance is reused",
    },
    Stage {
        step: 15,
        name: "AUDIT APPEND",
        file: Some("qqq-host/src/audit.rs"),
        symbol: Some("record"),
        // Complete, hash-chained, append-only, and called by nothing but its own
        // tests. This is the gap that matters most for §4.4's security story:
        // step 13 meters and step 15 records, and the recording half does not run.
        status: Status::BuiltUnwired,
        gap: "AuditStream has no production caller, so no capability-use record is written",
    },
];

/// A row of [`STAGES`] that [`audit`] could not verify, and why.
///
/// The `Unaccountable` variant is the one that used to be silent: `audit` skipped
/// any row that named neither a file nor a symbol, so a row could be added to the
/// table claiming `Implemented` and naming nothing, and the audit would report
/// clean. A row that cannot be checked is itself a finding — `§O-245`.
///
/// ```
/// use qqq_serve::lifecycle::{audit, Missing, STAGES};
///
/// let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
///     .parent()
///     .and_then(std::path::Path::parent)
///     .expect("crates/<name>/ has two parents");
/// let findings = audit(root);
/// // The one `Absent` row names nothing, and is reported for it rather than skipped.
/// assert!(findings.iter().any(|m| m.is_unaccountable()));
/// // No row claiming completeness is unaccountable on the real table.
/// assert!(findings.iter().filter(|m| m.is_defect()).count() <= 1);
/// assert_eq!(STAGES.len(), 15);
/// # let _ = Missing::Unnamed { step: 1, file: "f.rs", symbol: "s" };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Missing {
    /// The row names a file and a symbol, and the symbol is not in that file (or the
    /// file cannot be read).
    Unnamed {
        /// The §4.4 step number.
        step: u8,
        /// The file the table names.
        file: &'static str,
        /// The symbol the table names.
        symbol: &'static str,
    },
    /// The row names neither a file nor a symbol, so nothing about it can be
    /// checked. Only [`Status::Absent`] rows are legitimately in this shape; any
    /// other status here is the defect this variant exists to catch.
    Unaccountable {
        /// The §4.4 step number.
        step: u8,
        /// The step's name, so a report can identify the row without a lookup.
        name: &'static str,
        /// The status the row claims while naming nothing to check it against.
        status: Status,
    },
}

impl Missing {
    /// The §4.4 step number, whichever kind of finding this is.
    #[must_use]
    pub const fn step(&self) -> u8 {
        match self {
            Self::Unnamed { step, .. } | Self::Unaccountable { step, .. } => *step,
        }
    }

    /// Whether this finding is a row that named nothing to check.
    #[must_use]
    pub const fn is_unaccountable(&self) -> bool {
        matches!(self, Self::Unaccountable { .. })
    }

    /// Whether this finding is a real defect rather than the legitimate empty shape
    /// of an [`Status::Absent`] row.
    ///
    /// The distinction matters because `every_named_symbol_exists_in_its_named_file`
    /// must stay green on a correct table that contains one absent row, while still
    /// failing on a row that claims completion and names nothing.
    #[must_use]
    pub const fn is_defect(&self) -> bool {
        match self {
            Self::Unnamed { .. } => true,
            Self::Unaccountable { status, .. } => !matches!(status, Status::Absent),
        }
    }
}

impl fmt::Display for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unnamed { step, file, symbol } => write!(
                f,
                "step {step} names `{symbol}` in `{file}`, which is not there"
            ),
            Self::Unaccountable { step, name, status } => write!(
                f,
                "step {step} `{name}` claims `{status}` and names no file or symbol, \
                 so nothing about it can be checked"
            ),
        }
    }
}

/// A summary of the pipeline's completeness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// How many steps are fully implemented.
    pub implemented: usize,
    /// How many are partially implemented.
    pub partial: usize,
    /// How many are built but unreachable.
    pub built_unwired: usize,
    /// How many are absent.
    pub absent: usize,
}

impl Summary {
    /// Fold [`STAGES`] into counts.
    ///
    /// Delegates to [`Counts::of`], which is the **single** fold of the table. Two
    /// ways of counting the same table is exactly how `ARCH-011`'s three disagreeing
    /// count sites came to exist, so this one is a view of that one and
    /// `counts_agree_with_their_lists` asserts they cannot diverge.
    #[must_use]
    pub fn of(stages: &[Stage]) -> Self {
        Counts::of(stages).summary
    }

    /// Whether every step is complete and reachable.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.implemented == STAGES.len()
    }
}

/// The counts **and** the step lists §4.4's prose states, derived from one fold of
/// [`STAGES`].
///
/// # Why this type exists
///
/// `ARCH-011`'s earlier form hand-wrote the same four counts in three places — the
/// module doc comment, the checklist entry, and this file's prose — and they
/// disagreed: the comment said steps 2, 6, 8, 10, 14 were implemented, the checklist
/// said `5 implemented, 9 partial, 1 built-unwired, 1 absent`, and the table held
/// three implemented steps. Editing the three sets into agreement would leave three
/// places to drift again. So the numbers come from [`Self::of`] alone, and
/// `the_documented_counts_match_the_table` asserts the prose against
/// [`Self::documented`] — `§O-244`.
///
/// The tests in this file are compiled into the binary, so they cannot read the
/// checklist. That is why the checklist is compared from the other direction: the
/// documented checker reads this same string out of the source. Two mechanisms, one
/// counting site.
///
/// ```
/// use qqq_serve::lifecycle::Counts;
///
/// let counts = Counts::measured();
/// // The step lists and the numbers come from one fold, so they cannot disagree.
/// assert_eq!(counts.summary.implemented, counts.implemented.len());
/// assert_eq!(
///     counts.implemented.len()
///         + counts.partial.len()
///         + counts.built_unwired.len()
///         + counts.absent.len(),
///     15,
/// );
/// # let _ = qqq_serve::lifecycle::documented_cells();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counts {
    /// The four numbers, in the order [`Summary::Display`] renders them.
    pub summary: Summary,
    /// The `Implemented` rows, ascending by step number.
    pub implemented: Vec<u8>,
    /// The `Partial` rows, ascending by step number.
    pub partial: Vec<u8>,
    /// The `BuiltUnwired` rows, ascending by step number.
    pub built_unwired: Vec<u8>,
    /// The `Absent` rows, ascending by step number.
    pub absent: Vec<u8>,
}

impl Counts {
    /// Fold a table into counts and step lists, in one pass.
    ///
    /// The lists are the same fold as the numbers rather than a second traversal, so
    /// a list and its count cannot disagree.
    ///
    /// ```
    /// use qqq_serve::lifecycle::{Counts, Stage, Status};
    ///
    /// let table = [
    ///     Stage { step: 1, name: "ONE", file: Some("f.rs"), symbol: Some("s"),
    ///             status: Status::Implemented, gap: "" },
    ///     Stage { step: 2, name: "TWO", file: Some("f.rs"), symbol: Some("t"),
    ///             status: Status::Absent, gap: "no code" },
    /// ];
    /// let counts = Counts::of(&table);
    /// assert_eq!(counts.implemented, vec![1]);
    /// assert_eq!(counts.absent, vec![2]);
    /// assert_eq!(counts.summary.implemented, 1);
    /// ```
    #[must_use]
    pub fn of(stages: &[Stage]) -> Self {
        let mut implemented = Vec::new();
        let mut partial = Vec::new();
        let mut built_unwired = Vec::new();
        let mut absent = Vec::new();
        for s in stages {
            match s.status {
                Status::Implemented => implemented.push(s.step),
                Status::Partial => partial.push(s.step),
                Status::BuiltUnwired => built_unwired.push(s.step),
                Status::Absent => absent.push(s.step),
            }
        }
        let summary = Summary {
            implemented: implemented.len(),
            partial: partial.len(),
            built_unwired: built_unwired.len(),
            absent: absent.len(),
        };
        Self {
            summary,
            implemented,
            partial,
            built_unwired,
            absent,
        }
    }

    /// [`Self::of`] applied to the real table.
    ///
    /// ```
    /// use qqq_serve::lifecycle::Counts;
    ///
    /// let counts = Counts::measured();
    /// assert_eq!(counts.summary.implemented, counts.implemented.len());
    /// ```
    #[must_use]
    pub fn measured() -> Self {
        Self::of(&STAGES)
    }

    /// The exact sentence the module doc comment carries, as a table row.
    ///
    /// The doc comment writes the same four facts as Markdown table rows because it
    /// is documentation a human reads top to bottom. This produces the substance of
    /// those rows so the test can assert the prose agrees without the test having to
    /// parse Markdown.
    ///
    /// ```
    /// use qqq_serve::lifecycle::Counts;
    ///
    /// let documented = Counts::documented();
    /// assert!(documented.contains("Implemented | "));
    /// assert!(documented.ends_with("absent"));
    /// ```
    #[must_use]
    pub fn documented() -> String {
        let c = Self::measured();
        format!(
            "Implemented | {} |\nPartial | {} |\nBuilt, unwired | {} |\nAbsent | {} |\n{}",
            steps(&c.implemented),
            steps(&c.partial),
            steps(&c.built_unwired),
            steps(&c.absent),
            c.summary
        )
    }
}

/// The detail column of the documentation table, rendered from the table itself.
///
/// The [`Counts::documented`] row for `Implemented` is `Implemented | 2, 8, 10 |`
/// because that is how the Markdown row reads once split; the module doc comment
/// writes `| **Implemented** | 2, 8, 10 | The named symbol performs the step |` for
/// the same fact. This is the middle cell the doc comment must carry, so the two
/// renderings are compared cell by cell rather than as one string.
///
/// ```
/// use qqq_serve::lifecycle::documented_cells;
///
/// for (kind, steps) in documented_cells() {
///     assert!(!kind.is_empty());
///     // Every kind has at least one step on the current table.
///     assert!(!steps.is_empty());
/// }
/// ```
#[must_use]
pub fn documented_cells() -> Vec<(&'static str, String)> {
    let c = Counts::measured();
    vec![
        ("Implemented", steps(&c.implemented)),
        ("Partial", steps(&c.partial)),
        ("Built, unwired", steps(&c.built_unwired)),
        ("Absent", steps(&c.absent)),
    ]
}

/// Render a step list the way the documentation states it — `2, 6, 8, 10, 14`.
fn steps(list: &[u8]) -> String {
    list.iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} implemented, {} partial, {} built-unwired, {} absent",
            self.implemented, self.partial, self.built_unwired, self.absent
        )
    }
}

/// Check that every symbol [`STAGES`] names still exists in the file it names, and
/// that every row names something checkable in the first place.
///
/// # What this verifies, and what it deliberately does not
///
/// It verifies **the table still describes the tree**, which is the property a
/// later edit breaks: rename `build_linker`, or move the file, and every row stays
/// green while pointing at nothing. It does **not** verify the `status` field,
/// because whether a step is complete is a judgement about behaviour and no
/// substring search can make it.
///
/// That division is deliberate rather than a limitation to apologise for. A check
/// that claimed to verify the statuses would be the more dangerous kind of green
/// result (`§O-229`), so this one asserts only what it can see and the statuses are
/// re-read by a human when the code changes.
///
/// # The two ways a row is reported
///
/// A row naming a symbol that is not in its file is [`Missing::Unnamed`]. A row
/// naming **neither** a file nor a symbol is [`Missing::Unaccountable`] — reported
/// rather than skipped, because skipping it let a row claim [`Status::Implemented`]
/// while naming nothing to check. The only rows legitimately in that shape are
/// [`Status::Absent`] ones, and they are reported too so that a caller reading the
/// full list sees the reason they were not checked; `the_only_unaccountable_row_is
/// _the_absent_one` pins that.
///
/// # The containment check's known limit
///
/// `text.contains(symbol)` is satisfied by the symbol appearing **anywhere** in the
/// file, including in a comment or a string literal. That is a real weakness and it
/// is **kept, and named here**, rather than closed — see `§O-246` for the decision
/// and its reason. In short: every cheaper fix is either still a substring test or
/// drags a Rust parser into a test that must run on three operating systems, and
/// the property this function is responsible for is the table's *shape*, not symbol
/// identity.
///
/// `root` is the workspace root — the directory containing `crates/`.
#[must_use]
pub fn audit(root: &std::path::Path) -> Vec<Missing> {
    audit_stages(&STAGES, root)
}

/// [`audit`], over an arbitrary table.
///
/// Split out so a test can hand it a fabricated table and a fabricated root, and
/// assert exactly what it reports without depending on the repository's state.
///
/// ```
/// use qqq_serve::lifecycle::{audit_stages, Stage, Status};
///
/// // A fabricated table against a fabricated, empty root: the answer depends only
/// // on the table, not on the repository.
/// let table = [Stage {
///     step: 7,
///     name: "CLAIMS DONE",
///     file: None,
///     symbol: None,
///     status: Status::Implemented,
///     gap: "",
/// }];
/// let root = std::path::Path::new("target/fabricated-doc-root");
/// let findings = audit_stages(&table, root);
/// assert_eq!(findings.len(), 1);
/// assert!(findings[0].is_unaccountable());
/// assert!(findings[0].is_defect());
/// ```
#[must_use]
pub fn audit_stages(stages: &[Stage], root: &std::path::Path) -> Vec<Missing> {
    let mut missing = Vec::new();
    for stage in stages {
        let (Some(file), Some(symbol)) = (stage.file, stage.symbol) else {
            // A row that names neither is reported, not skipped: `§O-245`. An
            // `Absent` row is the legitimately empty shape; any other status here is
            // a row claiming a completeness it names nothing to support.
            missing.push(Missing::Unaccountable {
                step: stage.step,
                name: stage.name,
                status: stage.status,
            });
            continue;
        };
        let path = root.join("crates").join(file);
        let Ok(text) = std::fs::read_to_string(&path) else {
            missing.push(Missing::Unnamed {
                step: stage.step,
                file,
                symbol,
            });
            continue;
        };
        if !text.contains(symbol) {
            missing.push(Missing::Unnamed {
                step: stage.step,
                file,
                symbol,
            });
        }
    }
    missing
}

/// The `Unaccountable` findings among [`audit`]'s output — the rows that named
/// nothing to check.
///
/// Every one of these is a defect except a [`Status::Absent`] row, which is the
/// shape §4.4's missing step legitimately has. This is the function a gate should
/// read: `audit` reporting an empty list is the clean state, but `audit` reporting
/// only `Unnamed` findings while an `Implemented` row named nothing is the failure
/// the previous version of this function could not see.
///
/// ```
/// use qqq_serve::lifecycle::unaccountable_rows;
///
/// let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
///     .parent()
///     .and_then(std::path::Path::parent)
///     .expect("crates/<name>/ has two parents");
/// // On the real table, no row claims a completeness it names nothing to support.
/// assert!(unaccountable_rows(root).is_empty());
/// ```
#[must_use]
pub fn unaccountable_rows(root: &std::path::Path) -> Vec<Missing> {
    audit(root)
        .into_iter()
        .filter(Missing::is_unaccountable)
        .filter(|m| {
            !matches!(
                m,
                Missing::Unaccountable {
                    status: Status::Absent,
                    ..
                }
            )
        })
        .collect()
}

/// Render the pipeline as a table, for a human reading a run report.
#[must_use]
pub fn render() -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = writeln!(out, "{:>4}  {:<20} {:<11} where", "step", "name", "status");
    out.push_str(&"-".repeat(84));
    out.push('\n');
    for s in &STAGES {
        let where_ = match (s.file, s.symbol) {
            (Some(f), Some(sym)) => format!("{f}::{sym}"),
            _ => "—".to_owned(),
        };
        let _ = writeln!(
            out,
            "{:>4}  {:<20} {:<11} {}",
            s.step,
            s.name,
            s.status.label(),
            where_
        );
    }
    out.push_str(&"-".repeat(84));
    out.push('\n');
    let _ = writeln!(out, "{}", Summary::of(&STAGES));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table has exactly the fifteen steps §4.4 lists, numbered 1 to 15 with no
    /// gap and no repeat.
    #[test]
    fn the_table_has_all_fifteen_steps_in_order() {
        assert_eq!(
            STAGES.len(),
            15,
            "§4.4 lists fifteen steps; a table with a different count has lost or \
             invented one"
        );
        for (i, stage) in STAGES.iter().enumerate() {
            assert_eq!(
                stage.step as usize,
                i + 1,
                "step numbers must run 1..=15 with no gap; `{}` is at index {i}",
                stage.name
            );
        }
    }

    /// The names are verbatim from §4.4's diagram.
    ///
    /// The list is written out rather than derived, so a rename has to be made in
    /// two places — which is the point: this test fails if the table drifts from
    /// the document, and the document is the specification.
    #[test]
    fn the_step_names_are_verbatim_from_the_proposal() {
        const FROM_DOC: [&str; 15] = [
            "LISTENER SHARD",
            "HTTP PARSE",
            "ROUTE MATCH",
            "TENANT RESOLVE",
            "POLICY CHECK",
            "INSTANCE ACQUIRE",
            "CAPABILITY BIND",
            "LIMIT BIND",
            "REQUEST ADAPT",
            "GUEST ENTRY",
            "HOST CALLS",
            "RESPONSE ADAPT",
            "METER + TRACE",
            "INSTANCE RELEASE",
            "AUDIT APPEND",
        ];
        for (stage, want) in STAGES.iter().zip(FROM_DOC) {
            assert_eq!(
                stage.name, want,
                "step {} is named `{}` in §4.4 but `{}` here",
                stage.step, want, stage.name
            );
        }
    }

    /// A row that is not `Implemented` must say what is missing, and a row that is
    /// must not.
    ///
    /// This is what keeps the `gap` field from decaying into a second place where
    /// "done" is recorded: a completed row carrying a stale gap would contradict
    /// itself.
    #[test]
    fn every_incomplete_step_names_its_gap() {
        for stage in &STAGES {
            if stage.status.is_done() {
                assert!(
                    stage.gap.is_empty(),
                    "step {} is `{}` but carries a gap: {:?}",
                    stage.step,
                    stage.status,
                    stage.gap
                );
            } else {
                assert!(
                    !stage.gap.is_empty(),
                    "step {} is `{}` and does not say what is missing — an \
                     incomplete step with no stated gap is the shape that reads as \
                     complete",
                    stage.step,
                    stage.status
                );
            }
        }
    }

    /// A step with a file has a symbol and the reverse, so a half-filled row cannot
    /// slip through [`audit`] unchecked.
    #[test]
    fn a_row_names_both_a_file_and_a_symbol_or_neither() {
        for stage in &STAGES {
            assert_eq!(
                stage.file.is_some(),
                stage.symbol.is_some(),
                "step {} names a file without a symbol, or the reverse; a half-filled \
                 row would escape the check it looks like it satisfies",
                stage.step
            );
        }
    }

    /// A row that names neither a file nor a symbol is **reported**, and the only row
    /// in that shape is the absent one.
    ///
    /// Before `§O-245` the loop `continue`d here, so a row could be added claiming
    /// `Implemented` and naming nothing, and `audit` would return an empty list. This
    /// test is what makes that impossible: the unaccountable rows are enumerated, and
    /// the set is pinned to exactly the one legitimate member.
    #[test]
    fn the_only_unaccountable_row_is_the_absent_one() {
        let root = workspace_root();
        let unaccountable: Vec<_> = audit(&root)
            .into_iter()
            .filter(Missing::is_unaccountable)
            .collect();
        assert_eq!(
            unaccountable.len(),
            Counts::measured().absent.len(),
            "every `Absent` row names nothing and is reported for it; an \
             unaccountable row with any other status is a row claiming completeness \
             it names nothing to support. Found: {unaccountable:?}"
        );
        for m in &unaccountable {
            assert!(
                matches!(
                    m,
                    Missing::Unaccountable {
                        status: Status::Absent,
                        ..
                    }
                ),
                "only an `Absent` row may name neither a file nor a symbol: {m}"
            );
        }
        assert!(
            unaccountable_rows(&root).is_empty(),
            "no non-`Absent` row may claim a completeness it does not name: {:?}",
            unaccountable_rows(&root)
        );
    }

    /// `audit_stages` reports a row that names a file but no symbol, rather than
    /// skipping it.
    ///
    /// The root is fabricated, so this asserts on the function's own behaviour and
    /// not on the repository's state.
    #[test]
    fn a_row_that_names_a_file_without_a_symbol_is_reported() {
        let root = fabricated_root();
        let stages = [Stage {
            step: 41,
            name: "HALF FILLED",
            file: Some("qqq-serve/src/http1.rs"),
            symbol: None,
            status: Status::Implemented,
            gap: "",
        }];
        let found = audit_stages(&stages, &root);
        assert_eq!(
            found.len(),
            1,
            "a row naming a file but no symbol must be reported, not skipped: {found:?}"
        );
        assert!(found[0].is_unaccountable(), "{found:?}");
        assert_eq!(found[0].step(), 41);
    }

    /// `audit_stages` reports a row that names a symbol but no file, rather than
    /// skipping it — the converse of the case above, which an asymmetric bug would
    /// pass.
    #[test]
    fn a_row_that_names_a_symbol_without_a_file_is_reported() {
        let root = fabricated_root();
        let stages = [Stage {
            step: 42,
            name: "HALF FILLED AGAIN",
            file: None,
            symbol: Some("parse_head"),
            status: Status::Implemented,
            gap: "",
        }];
        let found = audit_stages(&stages, &root);
        assert_eq!(
            found.len(),
            1,
            "a row naming a symbol but no file must be reported: {found:?}"
        );
        assert!(found[0].is_unaccountable(), "{found:?}");
        assert_eq!(found[0].step(), 42);
    }

    /// An `Implemented` row that names neither file nor symbol is reported, and it is
    /// the case the old `continue` let through.
    #[test]
    fn an_implemented_row_that_names_nothing_is_reported() {
        let root = fabricated_root();
        let stages = [Stage {
            step: 43,
            name: "CLAIMS DONE",
            file: None,
            symbol: None,
            status: Status::Implemented,
            gap: "",
        }];
        let found = audit_stages(&stages, &root);
        assert_eq!(
            found.len(),
            1,
            "an `Implemented` row naming nothing is the defect this variant exists \
             for: {found:?}"
        );
        assert!(found[0].is_unaccountable(), "{found:?}");
    }

    /// The four counts the module documentation states are the counts the table
    /// produces.
    ///
    /// **This is the test that makes a hand-written count impossible to drift again.**
    /// It reads the doc comment out of this source file and asserts that the step
    /// lists in it are exactly what [`Counts::measured`] renders. Change one row's
    /// `Status` and this fails until the documentation is corrected — which is the
    /// intended outcome, since both a stale table and stale prose are defects.
    #[test]
    fn the_documented_counts_match_the_table() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lifecycle.rs"),
        )
        .expect("this source file is readable");
        let documented = Counts::documented();
        let rows: Vec<&str> = documented.lines().take(4).collect();

        for ((kind, list), row) in documented_cells().iter().zip(&rows) {
            // The doc comment writes the row as a Markdown table row:
            // `| **Implemented** | 2, 8, 10 | The named symbol performs the step |`.
            // The middle cell is the fact, so it is what is compared.
            let cell = format!("| {list} |");
            assert!(
                src.contains(&cell),
                "the module documentation carries no `{cell}` row, which is the step \
                 list the `STAGES` table produces for `{kind}`. The table and the \
                 prose have drifted apart; correct whichever is wrong. Derived rows: \
                 {rows:?}"
            );
            assert!(
                !list.trim().is_empty(),
                "a documented row with an empty step list states a count nowhere: {row}"
            );
        }
        let summary = documented
            .lines()
            .next_back()
            .expect("the last documented line is the summary");
        assert!(
            src.contains(summary),
            "the module documentation must state `{summary}` verbatim"
        );

        // The narrative sentence above the table states the same fact a third way — "would
        // have been false for **N** of the fifteen" — and it was the one reading of this
        // table with **no owner**: the four table rows and the summary line were compared,
        // the sentence was not. It said `twelve` while step 10 was `Implemented`; moving
        // step 10 to `Partial` made it need `thirteen`, and nothing would have said so.
        // A count in prose that nothing compares is exactly the defect this test exists for
        // (`§O-277`), so it is compared here too.
        let not_done = STAGES.len() - Counts::measured().summary.implemented;
        let narrative = format!("false for **{not_done}** of the fifteen");
        assert!(
            src.contains(&narrative),
            "the module documentation must state `{narrative}`: the `STAGES` table leaves \
             {not_done} of {} steps unimplemented, and the sentence above the table states \
             that same fact in prose. Correct whichever is wrong.",
            STAGES.len()
        );
    }

    /// [`Counts`] derives its lists and its numbers from one fold, so a list can
    /// never disagree with its count.
    #[test]
    fn counts_agree_with_their_lists() {
        let c = Counts::measured();
        assert_eq!(c.summary.implemented, c.implemented.len());
        assert_eq!(c.summary.partial, c.partial.len());
        assert_eq!(c.summary.built_unwired, c.built_unwired.len());
        assert_eq!(c.summary.absent, c.absent.len());
        let total = c.implemented.len() + c.partial.len() + c.built_unwired.len() + c.absent.len();
        assert_eq!(
            total,
            STAGES.len(),
            "every step appears in exactly one list"
        );
        assert_eq!(
            c.summary,
            Summary::of(&STAGES),
            "the two counting entry points must agree; if they can disagree, one of \
             them is a second counting site"
        );
    }

    /// Every symbol the table names exists in the file it names, checked against
    /// the real tree.
    #[test]
    fn every_named_symbol_exists_in_its_named_file() {
        let root = workspace_root();
        let defects: Vec<_> = audit(&root)
            .into_iter()
            .filter(Missing::is_defect)
            .collect();
        assert!(
            defects.is_empty(),
            "{} row(s) of STAGES name a symbol that is not in the file they name, or \
             claim a completeness they name nothing to support: {}",
            defects.len(),
            defects
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        );
    }

    /// A row claiming completion while naming nothing is reported as a defect, so the
    /// check above cannot be satisfied by a table that names nothing anywhere.
    #[test]
    fn a_done_row_that_names_nothing_is_a_defect() {
        let root = fabricated_root();
        let stages = [Stage {
            step: 44,
            name: "SILENT COMPLETION",
            file: None,
            symbol: None,
            status: Status::Implemented,
            gap: "",
        }];
        let defects: Vec<_> = audit_stages(&stages, &root)
            .into_iter()
            .filter(Missing::is_defect)
            .collect();
        assert_eq!(
            defects.len(),
            1,
            "a `Implemented` row naming nothing must be a defect: {defects:?}"
        );
    }

    /// An `Absent` row is not a defect, so the check above stays green on a correct
    /// table that contains one.
    #[test]
    fn an_absent_row_is_not_a_defect() {
        let root = fabricated_root();
        let stages = [Stage {
            step: 45,
            name: "ABSENT",
            file: None,
            symbol: None,
            status: Status::Absent,
            gap: "nothing exists",
        }];
        assert!(
            audit_stages(&stages, &root)
                .into_iter()
                .all(|m| !m.is_defect()),
            "an `Absent` row naming nothing is the legitimate shape, not a defect"
        );
    }

    /// `audit` reports a symbol that is not there, rather than passing silently.
    ///
    /// Without this, `every_named_symbol_exists_in_its_named_file` could pass
    /// because `audit` returns empty for every input — the control `§O-229`
    /// requires.
    #[test]
    fn the_audit_reports_a_symbol_that_does_not_exist() {
        let root = workspace_root();
        // A fabricated table naming a real file with a symbol that is not in it.
        let stages = [Stage {
            step: 99,
            name: "PROOF",
            file: Some("qqq-serve/src/http1.rs"),
            symbol: Some("a_symbol_that_does_not_exist_anywhere_99"),
            status: Status::Partial,
            gap: "control",
        }];
        let found = audit_stages(&stages, &root);
        assert_eq!(
            found.len(),
            1,
            "the audit must report the fabricated row: {found:?}"
        );
        assert!(
            matches!(found[0], Missing::Unnamed { step: 99, .. }),
            "the finding must be the `Unnamed` kind, naming the symbol it could not \
             find: {found:?}"
        );
        // The control is only meaningful if the file really is readable and really
        // does not contain the symbol — otherwise the pass above proves nothing.
        let text = std::fs::read_to_string(root.join("crates/qqq-serve/src/http1.rs"))
            .expect("the control's file exists");
        assert!(
            !text.contains("a_symbol_that_does_not_exist_anywhere_99"),
            "the positive control failed: its file contains the symbol string, so a \
             pass proves nothing"
        );
    }

    /// The summary counts every row exactly once.
    #[test]
    fn the_summary_accounts_for_every_step() {
        let s = Summary::of(&STAGES);
        assert_eq!(
            s.implemented + s.partial + s.built_unwired + s.absent,
            STAGES.len(),
            "the summary must account for all fifteen steps; a step counted twice \
             or not at all makes the completeness report wrong"
        );
    }

    /// The pipeline is **not** complete, and this test exists so that a future
    /// commit cannot quietly flip the claim.
    ///
    /// When `ARCH-011` is genuinely finished this assertion should be inverted
    /// deliberately, in the commit that finishes it — not deleted.
    #[test]
    fn the_pipeline_is_not_yet_complete_and_says_so() {
        let s = Summary::of(&STAGES);
        assert!(
            !s.is_complete(),
            "STAGES claims all fifteen steps are implemented. If that is now true, \
             invert this test in the same commit and record it; if it is not, the \
             statuses have been changed without the work being done."
        );
        assert!(
            s.absent + s.partial + s.built_unwired > 0,
            "at least one step must be reported incomplete until the work lands"
        );
    }

    /// The one `Absent` row is step 4, and it is absent for the stated reason.
    #[test]
    fn the_absent_step_is_the_tenant_resolve() {
        let absent: Vec<_> = STAGES
            .iter()
            .filter(|s| s.status == Status::Absent)
            .collect();
        assert_eq!(
            absent.len(),
            1,
            "expected exactly one absent step; found {}",
            absent.len()
        );
        assert_eq!(absent[0].step, 4);
        assert_eq!(absent[0].name, "TENANT RESOLVE");
        assert!(absent[0].file.is_none(), "an absent step names no file");
    }

    /// `render` mentions every step, so a report cannot silently drop one.
    #[test]
    fn the_rendered_table_mentions_every_step() {
        let out = render();
        for stage in &STAGES {
            assert!(
                out.contains(stage.name),
                "the rendered table omits `{}`",
                stage.name
            );
        }
        // The summary line is derived from STAGES rather than written out, so the
        // test states the relationship instead of a number that would have to be
        // updated whenever a step lands.
        let summary = Summary::of(&STAGES).to_string();
        assert!(
            out.contains(&summary),
            "the rendered table's summary line is `{summary}` and the render does not \
             contain it"
        );
    }

    /// A private, empty directory to hand [`audit_stages`] as its `root`.
    ///
    /// Used by the tests that assert on a **fabricated** table. Pointing those at the
    /// real workspace would make them depend on the repository's current state and
    /// turn a behavioural assertion into a vacuous one — the failure mode the plan
    /// names explicitly.
    fn fabricated_root() -> std::path::PathBuf {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/fabricated-audit-root");
        std::fs::create_dir_all(&dir).expect("a writable target directory");
        dir
    }

    /// The workspace root, found by walking up from the crate directory.
    ///
    /// `CARGO_MANIFEST_DIR` is the crate directory, so its parent's parent is the
    /// workspace root. Taken from the environment rather than by counting `..`
    /// segments from the current directory, because a test's working directory is
    /// not guaranteed.
    fn workspace_root() -> std::path::PathBuf {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        manifest
            .parent()
            .and_then(std::path::Path::parent)
            .expect("crates/<name>/ has two parents")
            .to_path_buf()
    }
}
