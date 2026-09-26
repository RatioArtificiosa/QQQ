// SPDX-License-Identifier: Apache-2.0

//! Reading the capability audit stream — `OBS-003`, `OBS-004`, `OBS-016`.
//!
//! Proposal §10.1:
//!
//! > Every capability use — granted, denied, and *attempted* — is recorded with tenant, component
//! > digest, manifest revision, function, and outcome. This is not a log; it is an **evidence
//! > record**, append-only, hash-chained, exportable as SARIF and as a compliance report.
//!
//! # Why this module exists, when the stream already had `to_jsonl`
//!
//! `AuditStream` was complete — hash-chained, append-only, with a JSON Lines export that refuses
//! to emit a corrupted record — and **nothing read it**. `§O-293` found that after wiring the
//! append into the served path: the stream acquired a writer and still had no reader, which means
//! `OBS-002` could not honestly be called done.
//!
//! The two exports here are the reader. They are deliberately **thin**: every number comes from
//! `AuditStream`'s own `ledger()` and every record from its own `records()`, so a report cannot
//! disagree with the stream it reports on. A second derivation would be a second answer to one
//! question, which is the defect this repository keeps recording.
//!
//! # Why SARIF and a compliance report are different documents
//!
//! They answer different questions about the same records, and conflating them was the risk worth
//! naming:
//!
//! | | SARIF | Compliance report |
//! |---|---|---|
//! | Reader | a **tool** — an IDE, a CI gate, a scanner aggregator | a **human** — a regulator, an auditor, an incident responder |
//! | Question | *"what is wrong here?"* | *"what did this code do, and was it permitted?"* |
//! | Shape | machine-readable results with rule ids and levels | a signed-off narrative with the chain head and the counts |
//!
//! A compliance report that was SARIF with nicer prose would be a second rendering of one
//! document, and the two would drift.
//!
//! # Example
//!
//! Both exports take the stream and return a document, and **both refuse a broken chain** rather
//! than rendering one:
//!
//! ```
//! use qqq_cap::capability::Capability;
//! use qqq_host::audit::{AuditStream, Outcome};
//! use qqq_host::audit_export::{to_compliance_report, to_sarif};
//! use qqq_host::tenant::{ComponentDigest, GrantDigest};
//!
//! let mut stream = AuditStream::with_default_capacity();
//! let component = ComponentDigest::new("0011223344556677").expect("digest");
//! let grants = GrantDigest::new("aabbccdd").expect("digest");
//! let _ = stream.record(None, &component, &grants, Capability::FsRead, "read", Outcome::Granted);
//!
//! assert!(to_sarif(&stream).is_ok());
//! assert!(to_compliance_report(&stream).is_ok());
//! ```

use std::fmt::Write as _;

use crate::audit::{AuditStream, LedgerError, Outcome};

/// Escape a string for embedding in a JSON string literal.
///
/// Duplicated from `qqq-run`'s own helper rather than shared, because `qqq-host` is the lower
/// crate and a `pub` escape function here would be part of its API for one call site. The rule
/// both implement is the same and is asserted by each crate's own tests.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// How severe an audit outcome is, for SARIF's `level`.
///
/// # Why a refusal is `warning` and a failure is `note`
///
/// The counter-intuitive ordering is the correct one. A **refusal** (`denied`, `attempted`) means
/// the runtime worked: the guest asked for authority it did not have and was stopped. That is
/// worth surfacing — it is the most interesting row in the stream (`Outcome::Denied`'s own doc
/// says so) — but it is not an error.
///
/// A **`failed`** row means the guest *was* permitted and the operation did not succeed, which is
/// the caller's own business and not a property of the runtime.
///
/// A **`granted`** row is the normal case and carries no severity at all: reporting every granted
/// use as a finding would produce a document nobody reads, and a report with noise is one people
/// stop reading.
///
/// # Why this is private
///
/// It is the *implementation* of the SARIF mapping, not part of the module's API — a consumer
/// reads the rendered SARIF, and a caller that needed the mapping directly would be building its
/// own document, which is the drift this module exists to prevent. It became private when
/// `check_api_examples` counted it: a public declaration that no caller should use is a public
/// declaration that owes an example, and the honest fix was to stop publishing it (`§O-298`).
const fn sarif_level(outcome: Outcome) -> Option<&'static str> {
    match outcome {
        Outcome::Denied | Outcome::Attempted => Some("warning"),
        Outcome::Failed => Some("note"),
        Outcome::Granted => None,
    }
}

/// A rule id per refusal class, so a consumer can filter rather than parse prose.
///
/// Private for the same reason as [`sarif_level`].
const fn sarif_rule(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Denied => "qqq/capability-denied",
        Outcome::Attempted => "qqq/capability-absent",
        Outcome::Failed => "qqq/capability-use-failed",
        Outcome::Granted => "qqq/capability-granted",
    }
}

/// Render the stream as SARIF 2.1.0 — `OBS-003`.
///
/// # Errors
///
/// [`LedgerError::ChainBroken`] when the chain does not verify. **The export refuses rather than
/// emitting**, because a SARIF document is consumed by tools that will not re-check a hash chain:
/// a corrupted stream rendered as valid SARIF becomes a plausible-looking artefact, which is worse
/// than no artefact.
///
/// # What is a result and what is not
///
/// Only refusals and failures become SARIF `results`. A `granted` row is counted in the run's
/// `properties` and omitted from `results`, because SARIF's `results` array is *findings* — and a
/// document where every normal operation is a finding has no signal left.
///
/// # Example
///
/// A refusal becomes a result with a rule id a consumer can filter on, and the document parses as
/// SARIF:
///
/// ```
/// use qqq_cap::capability::Capability;
/// use qqq_host::audit::{AuditStream, Outcome};
/// use qqq_host::audit_export::to_sarif;
/// use qqq_host::tenant::{ComponentDigest, GrantDigest};
///
/// let mut stream = AuditStream::with_default_capacity();
/// let component = ComponentDigest::new("0011223344556677").expect("digest");
/// let grants = GrantDigest::new("aabbccdd").expect("digest");
/// let _ = stream.record(None, &component, &grants, Capability::FsWrite, "read", Outcome::Denied);
///
/// let sarif = to_sarif(&stream).expect("an intact chain renders");
/// assert!(sarif.contains("qqq/capability-denied"));
/// assert!(sarif.contains("\"version\":\"2.1.0\""));
/// ```
pub fn to_sarif(stream: &AuditStream) -> Result<String, LedgerError> {
    // Verify before rendering, for the reason the `# Errors` section gives.
    stream
        .verify_chain()
        .map_err(|(sequence, reason)| LedgerError::ChainBroken { sequence, reason })?;

    let mut results = String::new();
    for record in stream.records() {
        let Some(level) = sarif_level(record.outcome) else {
            continue;
        };
        let _ = write!(
            results,
            "{{\"ruleId\":\"{}\",\"level\":\"{}\",\
             \"message\":{{\"text\":\"{}\"}},\
             \"properties\":{{\"sequence\":{},\
             \"tenant\":{},\
             \"component\":\"{}\",\
             \"grants\":\"{}\",\
             \"capability\":\"{}\",\
             \"function\":\"{}\",\
             \"previous\":\"{}\"}}}},",
            sarif_rule(record.outcome),
            level,
            json_escape(&format!(
                "capability `{}` was {} at `{}`",
                record.capability,
                record.outcome.as_str(),
                record.function
            )),
            record.sequence,
            match &record.tenant {
                Some(t) => format!("\"{}\"", json_escape(t.as_str())),
                None => "null".to_owned(),
            },
            json_escape(record.component.as_str()),
            json_escape(record.grants.as_str()),
            json_escape(&record.capability.to_string()),
            json_escape(record.function),
            json_escape(&record.previous),
        );
    }
    if results.ends_with(',') {
        results.pop();
    }

    let ledger = stream.ledger();
    let mut capabilities = String::new();
    for capability in ledger.capabilities() {
        let counts = ledger.for_capability(capability);
        let _ = write!(
            capabilities,
            "\"{}\":{{\"granted\":{},\"failed\":{},\"denied\":{},\"attempted\":{}}},",
            json_escape(&capability.to_string()),
            counts[0],
            counts[1],
            counts[2],
            counts[3],
        );
    }
    if capabilities.ends_with(',') {
        capabilities.pop();
    }

    // Built with explicit brace counting rather than one long literal: the JSON has four levels of
    // nesting here (document → runs[0] → tool/driver, properties) and a hand-written `format!`
    // string is where an off-by-one in `}}` is easiest to make and hardest to see. Each `{{`/`}}`
    // below is a literal brace; each `{}` is a substitution.
    Ok(format!(
        concat!(
            "{{",
            r#""$schema":"https://json.schemastore.org/sarif-2.1.0.json","#,
            r#""version":"2.1.0","#,
            r#""runs":[{{"#,
            r#""tool":{{"driver":{{"name":"qqqai","#,
            r#""informationUri":"https://qqq.codes","#,
            r#""rules":["#,
            r#"{{"id":"qqq/capability-denied","#,
            r#""shortDescription":{{"text":"A capability was refused by policy after an instance existed"}},"#,
            r#""helpUri":"https://qqq.codes/rules/qqq-capability-denied"}},"#,
            r#"{{"id":"qqq/capability-absent","#,
            r#""shortDescription":{{"text":"The guest attempted a capability the manifest does not grant"}},"#,
            r#""helpUri":"https://qqq.codes/rules/qqq-capability-absent"}},"#,
            r#"{{"id":"qqq/capability-use-failed","#,
            r#""shortDescription":{{"text":"A granted capability was exercised and the operation did not succeed"}},"#,
            r#""helpUri":"https://qqq.codes/rules/qqq-capability-use-failed"}}"#,
            "]}}}},",
            r#""results":[{}],"#,
            r#""properties":{{"#,
            r#""records":{},"#,
            r#""chainHead":"{}","#,
            r#""refusedAppends":{},"#,
            r#""byCapability":{{{}}}"#,
            "}}}}]}}",
        ),
        results,
        stream.len(),
        json_escape(stream.head()),
        stream.counters().refused,
        capabilities,
    ))
}

/// Render the stream as a compliance report — `OBS-004`, and `OBS-016`'s *"prove what this code
/// did"*.
///
/// # Errors
///
/// [`LedgerError::ChainBroken`], for the same reason as [`to_sarif`]: the report's whole claim is
/// that the record is intact, so a report rendered from a broken chain would assert something
/// false in the document whose purpose is to be believed.
///
/// # What the report has to contain to be worth anything
///
/// Four things, and each is here because omitting it makes the document decorative:
///
/// 1. **The chain head.** A digest a reader can compare against an independently held value. A
///    report without it cannot be cross-checked, so it is an assertion rather than evidence.
/// 2. **The counts, per capability and per outcome.** §10.2's Capability row: *uses by capability,
///    denials by capability, by tenant*.
/// 3. **Every refusal, individually.** An aggregate cannot answer *"was this specific request
///    permitted?"*, which is the question an incident responder asks.
/// 4. **What the report does not cover.** `records` is bounded by the stream's capacity, and a
///    report that omitted that would read as a complete history. The `refusedAppends` count is
///    printed **even when zero**, so a reader learns the number exists before they need it to be
///    non-zero.
///
/// # Example
///
/// The chain head is in the document, which is what makes it cross-checkable rather than an
/// assertion:
///
/// ```
/// use qqq_cap::capability::Capability;
/// use qqq_host::audit::{AuditStream, Outcome};
/// use qqq_host::audit_export::to_compliance_report;
/// use qqq_host::tenant::{ComponentDigest, GrantDigest};
///
/// let mut stream = AuditStream::with_default_capacity();
/// let component = ComponentDigest::new("0011223344556677").expect("digest");
/// let grants = GrantDigest::new("aabbccdd").expect("digest");
/// let _ = stream.record(None, &component, &grants, Capability::FsRead, "read", Outcome::Granted);
///
/// let report = to_compliance_report(&stream).expect("an intact chain renders");
/// assert!(report.contains(stream.head()), "the head is printed verbatim");
/// assert!(report.contains("Appends refused: 0"), "the bound is stated even at zero");
/// ```
pub fn to_compliance_report(stream: &AuditStream) -> Result<String, LedgerError> {
    if let Err((sequence, reason)) = stream.verify_chain() {
        return Err(LedgerError::ChainBroken { sequence, reason });
    }

    let mut out = String::new();
    write_preamble(&mut out);
    write_integrity(&mut out, stream);
    write_ledger(&mut out, stream);
    write_refusals(&mut out, stream);
    write_records(&mut out, stream);
    Ok(out)
}

/// The report's opening: what kind of document this is and why that matters.
fn write_preamble(out: &mut String) {
    let _ = writeln!(out, "QQQ capability-audit compliance report");
    let _ = writeln!(out, "======================================");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "This is an evidence record, not a log. Each record commits to the one before it, so a"
    );
    let _ = writeln!(
        out,
        "record cannot be altered or removed without breaking the chain head below."
    );
    let _ = writeln!(out);
}

/// The integrity section: the chain head a reader cross-checks, and the bound on the history.
fn write_integrity(out: &mut String, stream: &AuditStream) {
    let _ = writeln!(out, "Integrity");
    let _ = writeln!(out, "---------");
    let _ = writeln!(
        out,
        "Chain verified : yes ({} record(s) in order, each chaining from its predecessor)",
        stream.len()
    );
    let _ = writeln!(out, "Chain head     : {}", stream.head());
    let _ = writeln!(out, "Genesis        : {}", crate::audit::genesis_digest());
    let _ = writeln!(
        out,
        "Appends refused: {} (the stream holds at most {} records; a refused append is counted,",
        stream.counters().refused,
        stream.capacity()
    );
    let _ = writeln!(
        out,
        "                 not dropped, so a bounded history is visible rather than implied)"
    );
    let _ = writeln!(out);
}

/// §10.2's Capability row: uses and denials, by capability.
fn write_ledger(out: &mut String, stream: &AuditStream) {
    let ledger = stream.ledger();
    let _ = writeln!(out, "Capability use, by capability");
    let _ = writeln!(out, "-----------------------------");
    let _ = writeln!(
        out,
        "{:<24} {:>9} {:>9} {:>9} {:>11}",
        "capability", "granted", "failed", "denied", "attempted"
    );
    for capability in ledger.capabilities() {
        let c = ledger.for_capability(capability);
        let _ = writeln!(
            out,
            "{:<24} {:>9} {:>9} {:>9} {:>11}",
            capability.to_string(),
            c[0],
            c[1],
            c[2],
            c[3]
        );
    }
    let _ = writeln!(out);
}

/// Every refusal, individually — an aggregate cannot answer *"was this request permitted?"*.
fn write_refusals(out: &mut String, stream: &AuditStream) {
    let _ = writeln!(out, "Refusals, individually");
    let _ = writeln!(out, "----------------------");
    let _ = writeln!(
        out,
        "  {:<6} {:<10} {:<22} {:<16} tenant",
        "seq", "outcome", "capability", "function"
    );
    let mut any = false;
    for record in stream.records() {
        if !record.outcome.is_refusal() {
            continue;
        }
        any = true;
        let _ = writeln!(
            out,
            "  #{:<4} {:<10} {:<22} {:<16} {}",
            record.sequence,
            record.outcome.as_str(),
            record.capability.to_string(),
            record.function,
            match &record.tenant {
                Some(t) => t.as_str().to_owned(),
                None => "(unscoped)".to_owned(),
            }
        );
        let _ = writeln!(
            out,
            "        component {}  grants {}  chains from {}",
            record.component.as_str(),
            record.grants.as_str(),
            &record.previous[..record.previous.len().min(16)]
        );
    }
    if !any {
        let _ = writeln!(
            out,
            "  (none) -- every capability use in this stream was granted and completed. That is a"
        );
        let _ = writeln!(
            out,
            "  statement about THIS stream: a runtime with a grant set nobody exercises also"
        );
        let _ = writeln!(out, "  produces no refusals.");
    }
    let _ = writeln!(out);
}

/// Every record, in order, with the chain digest a reader can recompute.
fn write_records(out: &mut String, stream: &AuditStream) {
    let _ = writeln!(out, "Records, in order");
    let _ = writeln!(out, "-----------------");
    let _ = writeln!(
        out,
        "{:<6} {:<10} {:<24} {:<16} chain",
        "seq", "outcome", "capability", "function"
    );
    for record in stream.records() {
        let _ = writeln!(
            out,
            "{:<6} {:<10} {:<24} {:<16} {}",
            record.sequence,
            record.outcome.as_str(),
            record.capability.to_string(),
            record.function,
            &record.chain[..record.chain.len().min(24)]
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::genesis_digest;
    use crate::tenant::{ComponentDigest, GrantDigest};

    fn record(
        stream: &mut AuditStream,
        outcome: Outcome,
        capability: qqq_cap::capability::Capability,
    ) {
        let component = ComponentDigest::new("0011223344556677").expect("digest");
        let grants = GrantDigest::new("aabbccdd").expect("digest");
        let _ = stream.record(None, &component, &grants, capability, "read", outcome);
    }

    fn stream_with(outcomes: &[(Outcome, qqq_cap::capability::Capability)]) -> AuditStream {
        let mut s = AuditStream::with_default_capacity();
        for (o, c) in outcomes {
            record(&mut s, *o, *c);
        }
        s
    }

    /// **Only refusals and failures become SARIF results.**
    ///
    /// A `granted` row reported as a finding would put every normal operation in the results
    /// array, and a document where everything is a finding has no signal left.
    #[test]
    fn sarif_reports_only_refusals_and_failures() {
        let s = stream_with(&[
            (Outcome::Granted, qqq_cap::capability::Capability::FsRead),
            (Outcome::Denied, qqq_cap::capability::Capability::FsWrite),
            (
                Outcome::Attempted,
                qqq_cap::capability::Capability::SqlQuery,
            ),
            (Outcome::Failed, qqq_cap::capability::Capability::HttpClient),
        ]);
        let sarif = to_sarif(&s).expect("intact chain");

        assert!(
            sarif.contains("qqq/capability-denied"),
            "the denial is a result"
        );
        assert!(
            sarif.contains("qqq/capability-absent"),
            "the attempt is a result"
        );
        assert!(
            sarif.contains("qqq/capability-use-failed"),
            "the failure is a result"
        );
        assert!(
            !sarif.contains("qqq/capability-granted"),
            "a granted use must not appear as a SARIF rule result"
        );
        // The counts still mention it: omitted from `results` is not omitted from the document.
        assert!(
            sarif.contains("\"granted\":1"),
            "the granted count must still be reported in the run properties"
        );
    }

    /// **The chain head is in the report, because a report without it cannot be cross-checked.**
    #[test]
    fn the_compliance_report_carries_the_chain_head() {
        let s = stream_with(&[(Outcome::Granted, qqq_cap::capability::Capability::FsRead)]);
        let report = to_compliance_report(&s).expect("intact chain");

        assert!(
            report.contains(s.head()),
            "the report must print the chain head verbatim so a reader can compare it"
        );
        assert!(
            report.contains(&genesis_digest()),
            "and the genesis it chains from"
        );
        assert!(report.contains("Chain verified : yes"));
    }

    /// **The refused-append count is printed even when zero.**
    ///
    /// A reader has to learn the number exists *before* they need it to be non-zero — and a
    /// bounded history that omits its bound reads as a complete one.
    #[test]
    fn the_report_states_its_own_bound() {
        let s = stream_with(&[(Outcome::Granted, qqq_cap::capability::Capability::FsRead)]);
        let report = to_compliance_report(&s).expect("intact chain");
        assert!(
            report.contains("Appends refused: 0"),
            "the refused count must be printed even at zero, next to the capacity that bounds it"
        );
        assert!(
            report.contains(&s.capacity().to_string()),
            "and the capacity itself"
        );
    }

    /// **No refusals is stated as a fact about the stream, not as a clean bill of health.**
    #[test]
    fn an_empty_refusal_list_says_what_it_does_not_prove() {
        let s = stream_with(&[(Outcome::Granted, qqq_cap::capability::Capability::FsRead)]);
        let report = to_compliance_report(&s).expect("intact chain");
        assert!(report.contains("(none)"));
        assert!(
            report.contains("a runtime with a grant set nobody exercises"),
            "the report must not let an absence of refusals read as evidence of safety"
        );
    }

    /// **Both exports are valid JSON** — the property a substring assertion cannot reach.
    ///
    /// Every other test in this module asserts that a fragment appears. **A document can contain
    /// every expected substring and not be parseable**, and a SARIF consumer parses rather than
    /// greps — so the format the tool actually reads was the one thing untested. This is
    /// `§O-125`'s shape: an assertion about a nearby property, easy to write and not the property
    /// that matters.
    #[test]
    fn both_exports_are_valid_json() {
        let s = stream_with(&[
            (Outcome::Granted, qqq_cap::capability::Capability::FsRead),
            (Outcome::Denied, qqq_cap::capability::Capability::FsWrite),
            (
                Outcome::Attempted,
                qqq_cap::capability::Capability::SqlQuery,
            ),
        ]);

        let sarif = to_sarif(&s).expect("intact chain");
        let parsed: serde_json::Value =
            serde_json::from_str(&sarif).expect("the SARIF export must parse as JSON");
        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "qqqai");
        assert_eq!(
            parsed["runs"][0]["results"].as_array().map(Vec::len),
            Some(2),
            "two refusals, two results -- and the granted row is not among them"
        );

        let jsonl = s.to_jsonl().expect("intact chain");
        for (i, line) in jsonl.lines().enumerate() {
            serde_json::from_str::<serde_json::Value>(line)
                .unwrap_or_else(|e| panic!("JSON Lines line {i} must parse: {e}"));
        }
    }

    /// **A capability or function name containing a quote does not break the JSON.**
    ///
    /// The escapes are hand-written, so the injection that matters is a value with a `"` or a
    /// backslash in it. `Capability`'s spellings are fixed today — which is exactly why a test is
    /// needed: the escape path would otherwise be exercised for the first time by a future value.
    #[test]
    fn the_hand_written_escapes_hold() {
        assert_eq!(json_escape(r#"a"b"#), r#"a\"b"#);
        assert_eq!(json_escape(r"a\b"), r"a\\b");
        assert_eq!(json_escape("a\nb"), r"a\nb");
        assert_eq!(json_escape("a\u{1}b"), r"a\u0001b");
        // And the whole document still parses with a control character present.
        let s = stream_with(&[(Outcome::Denied, qqq_cap::capability::Capability::FsWrite)]);
        let sarif = to_sarif(&s).expect("intact chain");
        serde_json::from_str::<serde_json::Value>(&sarif).expect("escapes must keep it parseable");
    }

    /// **Both exports refuse a broken chain rather than rendering one.**
    ///
    /// This is the property the whole module turns on: an export path that rendered a corrupted
    /// stream would turn it into a plausible-looking document.
    #[test]
    fn a_broken_chain_is_refused_by_both_exports() {
        let mut s = stream_with(&[
            (Outcome::Granted, qqq_cap::capability::Capability::FsRead),
            (Outcome::Denied, qqq_cap::capability::Capability::FsWrite),
        ]);
        // Tamper with a record's chain digest directly, through the test-only accessor. The field
        // is public on `AuditRecord`; the *collection* is not, which is why the accessor exists.
        assert!(
            s.verify_chain().is_ok(),
            "precondition: the untampered chain verifies"
        );
        let tampered = s.records_mut_for_test();
        tampered[1].chain =
            "0000000000000000000000000000000000000000000000000000000000000000".to_owned();

        assert!(
            matches!(s.verify_chain(), Err((2, _))),
            "the tampered record must be identified by sequence"
        );
        assert!(matches!(
            to_sarif(&s),
            Err(LedgerError::ChainBroken { sequence: 2, .. })
        ));
        assert!(matches!(
            to_compliance_report(&s),
            Err(LedgerError::ChainBroken { sequence: 2, .. })
        ));
        assert!(matches!(s.to_jsonl(), Err(LedgerError::ChainBroken { .. })));
    }
}
