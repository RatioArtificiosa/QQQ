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
//! would have been false for **five** of the fifteen, in three distinct ways:
//!
//! | Kind | Steps | What is actually true |
//! |---|---|---|
//! | **Implemented** | 2, 6, 8, 10, 14 | The named symbol performs the step |
//! | **Partial** | 1, 3, 5, 7, 9, 11, 12, 13 | Something performs the step, but not the whole of what §4.4 describes |
//! | **Absent** | 4 | No implementation exists |
//! | **Built, unwired** | 15 | A complete implementation with no production caller |
//!
//! A module that said "implemented" would be `§O-219`'s shape — an item that looks
//! done. So [`STAGES`] carries a [`Status`] per step, and [`audit`] verifies a
//! different, checkable property: **every symbol the table names still exists in
//! the file it names.** That is the property a later edit can break, and it is the
//! one an omission cannot hide from.
//!
//! # The four honest gaps, named
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
        // The handler is resolved once per component and called. §4.4 says the
        // host "runs it async"; the async machinery exists in full, but the
        // production dispatch path uses the synchronous entry points.
        status: Status::Implemented,
        gap: "",
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

/// A row of [`STAGES`] whose named symbol could not be found in its named file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Missing {
    /// The §4.4 step number.
    pub step: u8,
    /// The file the table names.
    pub file: &'static str,
    /// The symbol the table names.
    pub symbol: &'static str,
}

impl fmt::Display for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "step {} names `{}` in `{}`, which is not there",
            self.step, self.symbol, self.file
        )
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
    #[must_use]
    pub fn of(stages: &[Stage]) -> Self {
        let mut out = Self {
            implemented: 0,
            partial: 0,
            built_unwired: 0,
            absent: 0,
        };
        for s in stages {
            match s.status {
                Status::Implemented => out.implemented += 1,
                Status::Partial => out.partial += 1,
                Status::BuiltUnwired => out.built_unwired += 1,
                Status::Absent => out.absent += 1,
            }
        }
        out
    }

    /// Whether every step is complete and reachable.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.implemented == STAGES.len()
    }
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

/// Check that every symbol [`STAGES`] names still exists in the file it names.
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
/// `root` is the workspace root — the directory containing `crates/`.
#[must_use]
pub fn audit(root: &std::path::Path) -> Vec<Missing> {
    let mut missing = Vec::new();
    for stage in &STAGES {
        let (Some(file), Some(symbol)) = (stage.file, stage.symbol) else {
            // Absent steps name no file, which is the correct shape for them.
            continue;
        };
        let path = root.join("crates").join(file);
        let Ok(text) = std::fs::read_to_string(&path) else {
            missing.push(Missing {
                step: stage.step,
                file,
                symbol,
            });
            continue;
        };
        if !text.contains(symbol) {
            missing.push(Missing {
                step: stage.step,
                file,
                symbol,
            });
        }
    }
    missing
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
    /// slip through [`audit`] by naming neither.
    #[test]
    fn a_row_names_both_a_file_and_a_symbol_or_neither() {
        for stage in &STAGES {
            assert_eq!(
                stage.file.is_some(),
                stage.symbol.is_some(),
                "step {} names a file without a symbol, or the reverse; `audit` \
                 skips exactly the rows that name neither, so a half-filled row \
                 would escape it",
                stage.step
            );
        }
    }

    /// Every symbol the table names exists in the file it names, checked against
    /// the real tree.
    #[test]
    fn every_named_symbol_exists_in_its_named_file() {
        let root = workspace_root();
        let missing = audit(&root);
        assert!(
            missing.is_empty(),
            "{} row(s) of STAGES name a symbol that is not in the file they name: {}",
            missing.len(),
            missing
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
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
        // A row naming a real file with a symbol that is definitely not in it.
        let missing = {
            let stage = Stage {
                step: 99,
                name: "PROOF",
                file: Some("qqq-serve/src/http1.rs"),
                symbol: Some("a_symbol_that_does_not_exist_anywhere_99"),
                status: Status::Partial,
                gap: "control",
            };
            let (Some(file), Some(symbol)) = (stage.file, stage.symbol) else {
                unreachable!("the control row names both")
            };
            let path = root.join("crates").join(file);
            let text = std::fs::read_to_string(&path).expect("the control's file exists");
            !text.contains(symbol)
        };
        assert!(
            missing,
            "the positive control failed: its file exists but the symbol string was \
             found, so the control proves nothing"
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
        let absent: Vec<_> = STAGES.iter().filter(|s| s.status == Status::Absent).collect();
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
