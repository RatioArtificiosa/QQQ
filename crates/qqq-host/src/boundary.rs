// SPDX-License-Identifier: Apache-2.0

//! Input validation at every guest-to-host boundary — `SEC-011`.
//!
//! # The requirement, and why "add checks" is not an implementation of it
//!
//! §2.2 NN-2 asks for validation at **every** guest-to-host boundary crossing.
//! The phrase doing the work is *every*. A validator that each host function
//! calls when its author remembers to is not a boundary layer — it is a set of
//! independent decisions that will diverge, and the divergence will be in the
//! function nobody thought to check.
//!
//! So the design here is **table-driven and centralised**, with the same shape
//! this project uses for its faults and its traversals: one place that knows all
//! the checks, one place a new boundary registers itself in, and one test that
//! fails when a boundary is added without a check.
//!
//! # What a boundary check is, and what it is not
//!
//! A guest-to-host crossing receives **guest-controlled values**: an integer, a
//! list, a string, a path, a handle. Every one is attacker-controlled, because
//! the guest is the attacker in §7.2's model. The checks fall into four classes,
//! and each has a distinct failure it prevents:
//!
//! | Class | Question | Failure it prevents |
//! |---|---|---|
//! | **Range** | Is this integer a member of a set the host defined? | Enum confusion; a discriminant the host will index with |
//! | **Size** | Is this within the budget the manifest set? | Host allocation on the guest's instruction |
//! | **Shape** | Is this a well-formed instance of its type? | Traversal, injection, a name that is not a name |
//! | **Consistency** | Do two supplied values agree? | The half-updated state a pair of unvalidated arguments creates |
//!
//! # The one rule that makes this enforceable rather than aspirational
//!
//! Every check returns a [`Verdict`], and [`Verdict::into_result`] produces an
//! error that **names the argument**. A validation failure is a *guest bug*, and
//! the operator reading the log has to be able to point at the guest's code. "The
//! argument was invalid" is not actionable; "the guest passed an invalid `path`:
//! contains a `..` component" is.
//!
//! # Why the limits are named constants in this module rather than inline
//!
//! Because a boundary limit is a **host** budget, not a manifest policy. The two
//! are different things and conflating them is a mistake this project has already
//! made once (see `§O-068` on why `max_subrequests` *is* a manifest field while
//! `WARN_THRESHOLD_PERCENT` is not): a manifest field is a number an operator may
//! raise, whereas these are the ceilings beyond which the host itself becomes the
//! victim — a name longer than the host will store, a list longer than the host
//! will index. An operator cannot raise them because they are not policy.
//!
//! See Proposal §2.2, §7.2, §6.1. Checklist `SEC-011`.

pub use crate::quota::Verdict;

/// The longest guest-supplied identifier the host will accept, in bytes.
///
/// # Why 256
///
/// Every identifier that crosses the boundary — a hash algorithm name, a
/// secret name, a route parameter, a key — is stored in a map, compared, and
/// logged. 256 bytes covers every legitimate case with two orders of magnitude to
/// spare (the longest name in the WIT corpus is 18 bytes), and it bounds the
/// host's per-call allocation. A host that accepted an unbounded name would let a
/// guest make the host allocate on command — the same defect class
/// [`MAX_LIST_ELEMENTS`] addresses, one dimension up.
pub const MAX_IDENTIFIER_BYTES: usize = 256;

/// The longest guest-supplied path the host will accept, in bytes.
///
/// Larger than [`MAX_IDENTIFIER_BYTES`] because real filesystem paths are
/// legitimately long, and smaller than any OS limit that matters so the host
/// refuses with its own diagnostic rather than the kernel's.
pub const MAX_PATH_BYTES: usize = 4096;

/// The most elements the host will accept in a single guest-supplied list.
///
/// # Why a count ceiling and a total-size ceiling are both needed
///
/// `MAX_LIST_BYTES` bounds the *bytes*; this bounds the *elements*. They are not
/// interchangeable: a list of 100 million empty strings is zero bytes of payload
/// and 100 million `String` headers, so a byte check alone would let a guest make
/// the host allocate ~2.4 GB of metadata from a few kilobytes of input. Each check
/// catches the shape the other misses.
pub const MAX_LIST_ELEMENTS: usize = 1_000_000;

/// The most bytes the host will accept across all elements of one list.
pub const MAX_LIST_BYTES: usize = 64 * 1024 * 1024;

/// A boundary argument that failed validation.
///
/// # Why this carries the field name and the value's *rendered* form
///
/// The field name is what makes the error actionable. The rendered value is
/// included because a guest bug is diagnosed by seeing what was actually passed —
/// but it is **truncated and escaped**, because echoing an attacker-controlled
/// value verbatim into a log is a log-injection vector, and echoing an unbounded
/// one is a memory-amplification vector. Both are real, and a helper that got
/// either wrong would be a boundary check that introduces a boundary bug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// The argument that failed, as the WIT names it.
    pub field: &'static str,
    /// Why it failed, phrased for the operator.
    pub reason: String,
}

impl Rejection {
    /// A rejection with a static reason.
    #[must_use]
    pub fn new(field: &'static str, reason: impl Into<String>) -> Self {
        Self {
            field,
            reason: reason.into(),
        }
    }
}

/// The longest value this module will echo into a diagnostic.
///
/// Deliberately small. A diagnostic exists to be read; an operator needs the
/// first few bytes to recognise the mistake, not the whole payload — and echoing
/// the whole payload is how a validation failure becomes a log-volume attack.
pub const MAX_ECHO_BYTES: usize = 64;

/// Render a guest value for a diagnostic, safely.
///
/// # Why this escapes rather than printing raw
///
/// A guest-supplied string containing a newline and `ERROR: disk full` produces a
/// log line indistinguishable from a genuine host error. That is log injection,
/// and it is a real attack on operators rather than a stylistic concern — the
/// operator's tooling parses lines, so a forged line is a forged event. Control
/// characters are therefore escaped and the result is truncated.
#[must_use]
pub fn render_for_diagnostic(value: &str) -> String {
    let mut out = String::with_capacity(value.len().min(MAX_ECHO_BYTES) + 3);
    let mut truncated = false;

    for ch in value.chars() {
        if out.len() >= MAX_ECHO_BYTES {
            truncated = true;
            break;
        }
        match ch {
            // Escape everything that could forge structure in a log consumer.
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                // Non-printable: show the code point rather than the byte, so a
                // reader can tell what it was. `write!` into the `String` rather
                // than `push_str(&format!(..))`, which allocates a temporary for
                // no reason — clippy's `format_push_string` says so and is right.
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }

    if truncated {
        out.push('…');
    }
    out
}

// ---------------------------------------------------------------------------
// Range checks
// ---------------------------------------------------------------------------

/// Validate an integer that the guest claims is a member of a host-defined set.
///
/// # Why this takes the valid range rather than a list
///
/// Every such set in the WIT corpus is a contiguous discriminant range: an
/// `enum` lowers to a `u32` in declaration order, and `variant` to a tagged
/// union. Taking `0..n` states the contract that actually exists. A caller with a
/// genuinely sparse set builds the check from [`one_of`] instead, and the two
/// functions together cover both shapes without one pretending to be the other.
#[must_use]
pub fn discriminant(field: &'static str, value: u32, count: u32) -> Verdict {
    if value < count {
        Verdict::Accept
    } else {
        Verdict::Reject {
            reason: format!(
                "{value} is not a valid discriminant; the set has {count} members \
                 (0..{count}), so the guest and host disagree about the type — which \
                 is a version mismatch, not a guest bug to retry"
            ),
        }
    }
    .with_field(field)
}

/// Validate that `value` is one of `allowed`.
///
/// # Why the error lists the allowed values
///
/// Because the alternative is an operator guessing. The list is host-defined and
/// small by construction, so printing it costs nothing and turns a rejection into
/// a specification the guest's author can code against.
#[must_use]
pub fn one_of(field: &'static str, value: &str, allowed: &[&str]) -> Verdict {
    if allowed.contains(&value) {
        Verdict::Accept
    } else {
        Verdict::Reject {
            reason: format!(
                "`{}` is not one of the permitted values: {}",
                render_for_diagnostic(value),
                allowed.join(", ")
            ),
        }
    }
    .with_field(field)
}

// ---------------------------------------------------------------------------
// Size checks
// ---------------------------------------------------------------------------

/// Validate that a guest-supplied byte sequence is within `max` bytes.
#[must_use]
pub fn size(field: &'static str, len: usize, max: usize) -> Verdict {
    if len <= max {
        Verdict::Accept
    } else {
        Verdict::Reject {
            reason: format!("{len} bytes exceeds the host's {max}-byte limit for this argument"),
        }
    }
    .with_field(field)
}

/// Validate a guest-supplied list on **both** axes.
///
/// # Why both, and why this is one function
///
/// [`MAX_LIST_ELEMENTS`] and [`MAX_LIST_BYTES`] each catch a shape the other
/// misses — see that constant. Splitting this into two functions would let a
/// caller use one and believe it had done the other, which is precisely the
/// failure a boundary layer exists to prevent. One function, both checks, and the
/// reason names whichever tripped.
#[must_use]
pub fn list_size(field: &'static str, elements: usize, total_bytes: usize) -> Verdict {
    if elements > MAX_LIST_ELEMENTS {
        return Verdict::Reject {
            reason: format!(
                "{elements} elements exceeds the host's {MAX_LIST_ELEMENTS}-element limit; \
                 a list of tiny elements can exhaust host memory without being large in bytes"
            ),
        }
        .with_field(field);
    }
    if total_bytes > MAX_LIST_BYTES {
        return Verdict::Reject {
            reason: format!(
                "{total_bytes} bytes exceeds the host's {MAX_LIST_BYTES}-byte limit; a list \
                 of few large elements can exhaust host memory without being long"
            ),
        }
        .with_field(field);
    }
    Verdict::Accept
}

/// Validate a guest-supplied string on length and content.
///
/// # What "content" means here, and what it deliberately does not
///
/// It rejects **control characters and NUL**, because those forge structure in
/// whatever consumes the string downstream — a log, a header, a filename, a
/// terminal. It does *not* reject "unusual" printable characters: a check that
/// refused non-ASCII would break every legitimate internationalised name, and the
/// places where a restricted alphabet is genuinely required (a route parameter, a
/// DNS label) have their own checks below that say so explicitly. Being strict
/// here because it "feels safer" would make the specific checks look redundant
/// while breaking real guests.
#[must_use]
pub fn text(field: &'static str, value: &str, max_bytes: usize) -> Verdict {
    if value.len() > max_bytes {
        return Verdict::Reject {
            reason: format!(
                "{} bytes exceeds the host's {max_bytes}-byte limit",
                value.len()
            ),
        }
        .with_field(field);
    }
    if value.is_empty() {
        return Verdict::Reject {
            reason: "is empty; an empty name or key cannot identify anything".to_owned(),
        }
        .with_field(field);
    }
    if let Some(bad) = value.chars().find(|c| c.is_control() || *c == '\0') {
        return Verdict::Reject {
            reason: format!(
                "contains a control character (U+{:04X}); control characters forge \
                 structure in whatever consumes the value downstream",
                bad as u32
            ),
        }
        .with_field(field);
    }
    Verdict::Accept
}

// ---------------------------------------------------------------------------
// Shape checks
// ---------------------------------------------------------------------------

/// Validate that a guest-supplied path contains no traversal.
///
/// # Why this duplicates `qqq_cap::normalize::path_is_within`
///
/// It does not duplicate the *containment* check; it performs the part that is
/// meaningful **without a root**. A boundary that has already resolved a path
/// against a granted root calls `path_is_within` with that root, and that is the
/// authoritative answer. A boundary that has *not* yet done so — because the path
/// is about to be looked up, or because it is being used as a key — needs to know
/// only that the guest did not try to escape, and this is that check.
///
/// The `§O-067` lesson is why it is not a prefix match: the previous
/// implementation of the containment check was a string-prefix test that admitted
/// every traversal, and its doc comment was the only argument that it was safe.
/// This one refuses on the **components**, and refuses `..` rather than resolving
/// it, because resolving `..` lexically is subtly wrong when a component is a
/// symlink and there is no filesystem here to ask.
#[must_use]
pub fn path_shape(field: &'static str, path: &str) -> Verdict {
    if path.is_empty() {
        return Verdict::Reject {
            reason: "is empty".to_owned(),
        }
        .with_field(field);
    }
    if path.len() > MAX_PATH_BYTES {
        return Verdict::Reject {
            reason: format!(
                "{} bytes exceeds the host's {MAX_PATH_BYTES}-byte limit",
                path.len()
            ),
        }
        .with_field(field);
    }
    if let Some(bad) = path.chars().find(|c| c.is_control() || *c == '\0') {
        return Verdict::Reject {
            reason: format!("contains a control character (U+{:04X})", bad as u32),
        }
        .with_field(field);
    }
    // Component-wise, so `..` is caught wherever it appears and a component that
    // merely *contains* dots (`..hidden`, `a..b`) is not falsely refused.
    if path.split(['/', '\\']).any(|component| component == "..") {
        return Verdict::Reject {
            reason: format!(
                "`{}` contains a `..` component; the host refuses to resolve it because \
                 resolving lexically is wrong when a component may be a symlink",
                render_for_diagnostic(path)
            ),
        }
        .with_field(field);
    }
    Verdict::Accept
}

/// Validate that a string is usable as a single path or DNS component.
///
/// # Why this is stricter than [`text`], on purpose
///
/// A route parameter and a DNS label both end up in a **structure** rather than
/// in a value: the first is spliced into a routing table, the second into a name
/// that a resolver interprets. Both therefore require a restricted alphabet, and
/// the restriction is a property of those positions rather than of strings
/// generally — which is exactly why it is a separate function with its own name
/// rather than a flag on [`text`].
///
/// Rejected by construction: separators, `.` and `..`, percent-encoding, and
/// anything outside `[A-Za-z0-9._-]`.
#[must_use]
pub fn path_component(field: &'static str, value: &str) -> Verdict {
    if value.is_empty() {
        return Verdict::Reject {
            reason: "is empty".to_owned(),
        }
        .with_field(field);
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Verdict::Reject {
            reason: format!(
                "{} bytes exceeds the host's {MAX_IDENTIFIER_BYTES}-byte limit",
                value.len()
            ),
        }
        .with_field(field);
    }
    if value == "." || value == ".." {
        return Verdict::Reject {
            reason: "is a path component that refers to a directory, not an entry".to_owned(),
        }
        .with_field(field);
    }
    if let Some(bad) = value
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
    {
        return Verdict::Reject {
            reason: format!(
                "contains `{}` (U+{:04X}); a path component admits only \
                 [A-Za-z0-9._-], because anything else is structure in the \
                 container it is spliced into rather than a character in a value",
                render_for_diagnostic(&bad.to_string()),
                bad as u32
            ),
        }
        .with_field(field);
    }
    Verdict::Accept
}

// ---------------------------------------------------------------------------
// Consistency checks
// ---------------------------------------------------------------------------

/// Validate that `offset + length` does not exceed `total`.
///
/// # Why this is its own check rather than two range checks
///
/// Because each operand can be individually valid and the pair still overflows.
/// `offset = 1000` and `length = 1000` are both fine against a `total` of 1500;
/// together they reach 2000. A boundary that validated the two separately would
/// pass them and then slice out of bounds — and the arithmetic primitive here is
/// `checked_add`, because an `offset + length` that wraps is the classic way this
/// check passes while the slice panics.
#[must_use]
pub fn range_within(field: &'static str, offset: u64, length: u64, total: u64) -> Verdict {
    match offset.checked_add(length) {
        Some(end) if end <= total => Verdict::Accept,
        Some(end) => Verdict::Reject {
            reason: format!(
                "offset {offset} + length {length} = {end} exceeds the available {total}; \
                 each operand is individually valid, which is why this is checked as a pair"
            ),
        }
        .with_field(field),
        None => Verdict::Reject {
            reason: format!(
                "offset {offset} + length {length} overflows u64; the guest supplied a \
                 range whose end cannot be represented"
            ),
        }
        .with_field(field),
    }
}

/// Validate that two guest-supplied values agree about a length.
///
/// # Why agreement is a security property and not just a sanity check
///
/// A pair like `(declared_length, actual_data)` is where a **length-extension**
/// bug lives: a host that trusts `declared_length` and reads that many bytes from
/// a shorter buffer reads past it, and one that trusts the buffer and ignores the
/// declaration truncates silently. Either way the two values disagreeing means one
/// of them is being believed over the other, and the guest chose which. Refusing
/// the disagreement removes the choice.
#[must_use]
pub fn consistent_length(field: &'static str, declared: u64, actual: u64) -> Verdict {
    if declared == actual {
        Verdict::Accept
    } else {
        Verdict::Reject {
            reason: format!(
                "the declared length {declared} disagrees with the actual {actual}; a host \
                 that trusted either one would read past a buffer or truncate silently, \
                 and the guest would have chosen which"
            ),
        }
        .with_field(field)
    }
}

/// Validate several verdicts, returning the first rejection.
///
/// # Why this exists rather than a loop at each call site
///
/// Because "which rejection wins" must be deterministic. Iterating a `Vec` gives
/// declaration order, which is stable and reviewable; a caller that instead
/// short-circuited on whichever check happened to run first would produce
/// diagnostics that vary with refactoring. Deterministic ordering is what makes a
/// validation failure reproducible from a log line.
#[must_use]
pub fn all(verdicts: &[Verdict]) -> Verdict {
    for v in verdicts {
        if v.is_reject() {
            return v.clone();
        }
    }
    Verdict::Accept
}

// ---------------------------------------------------------------------------
// The registry: every boundary, and the checks it performs
// ---------------------------------------------------------------------------

/// One guest-to-host boundary and the validation it performs.
///
/// # Why this is data rather than a comment
///
/// `SEC-011` says *every* crossing. A list of crossings in prose cannot be
/// checked, so it drifts the first time a boundary is added — and the boundary
/// whose author did not read the prose is exactly the one that has no check.
/// Stating the inventory as a table lets a test assert that every `func_wrap`
/// call site in the crate appears here, which turns "every" from a claim into a
/// check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Boundary {
    /// The registered function name, as passed to `func_wrap`.
    pub function: &'static str,
    /// The interface it belongs to.
    pub interface: &'static str,
    /// Which check classes this boundary applies.
    pub checks: &'static [CheckClass],
    /// What the guest controls here, for review.
    pub guest_controls: &'static str,
}

/// The four classes of validation, as an enum so the table can be exhaustive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckClass {
    /// Integer membership in a host-defined set.
    Range,
    /// Bounds on a length, a count or a byte total.
    Size,
    /// Well-formedness of a structured value.
    Shape,
    /// Agreement between two supplied values.
    Consistency,
}

impl Boundary {
    /// Whether this boundary applies `class`.
    #[must_use]
    pub fn applies(&self, class: CheckClass) -> bool {
        self.checks.contains(&class)
    }
}

/// Every guest-to-host boundary in `qqq-host`, with its validation.
///
/// # What `function` names, and why it is the bare registered name
///
/// `func_wrap` registers a function **within an interface instance**, so the name
/// passed is bare (`now`) while the guest-visible path is qualified
/// (`qqq:clock@1.0.0/wall-clock.now`). This table stores the bare name because
/// that is what the completeness test can match against the source, and the
/// interface field carries the qualification. Storing the qualified form instead
/// would make the test unable to verify the table — which it did, immediately:
/// the first version of this table used `wall-clock.now` and the registry test
/// reported every clock function as undeclared. **A table that cannot be checked
/// against the code is a document, not a control.**
///
/// # The two kinds of entry, and why both are first-class
///
/// A boundary either **validates** guest input or has **none to validate**. Both
/// must appear, because omitting the second kind would make this table unable to
/// distinguish "no input" from "not yet considered" — and the second is the state
/// that hides a missing check.
pub const BOUNDARIES: &[Boundary] = &[
    Boundary {
        function: "now",
        interface: "qqq:clock@1.0.0/wall-clock",
        checks: &[],
        guest_controls: "nothing: the call takes no arguments and the return is \
                         host-computed. Listed so the table is complete.",
    },
    Boundary {
        function: "resolution",
        interface: "qqq:clock@1.0.0/wall-clock",
        checks: &[],
        guest_controls: "nothing: no arguments.",
    },
    Boundary {
        function: "timezone",
        interface: "qqq:clock@1.0.0/wall-clock",
        checks: &[],
        guest_controls: "nothing: no arguments; the return is the fixed string UTC.",
    },
    Boundary {
        function: "now",
        interface: "qqq:clock@1.0.0/monotonic-clock",
        checks: &[],
        guest_controls: "nothing: no arguments.",
    },
    Boundary {
        function: "resolution",
        interface: "qqq:clock@1.0.0/monotonic-clock",
        checks: &[],
        guest_controls: "nothing: no arguments.",
    },
    Boundary {
        function: "get",
        interface: "qqq:crypto@1.0.0/random",
        // The `length` argument decides a host allocation, so it is a Size
        // boundary. `random_bytes` enforces the per-call maximum, and this table
        // is what makes that enforcement visible as a boundary property rather
        // than as an implementation detail of `ambient`.
        checks: &[CheckClass::Size],
        guest_controls: "`length`, which the host allocates for",
    },
    Boundary {
        function: "digest",
        interface: "qqq:crypto@1.0.0/hashing",
        // Range for the `algorithm` discriminant, Size for the input length.
        checks: &[CheckClass::Range, CheckClass::Size],
        guest_controls: "`algorithm` (a discriminant) and `data` (up to MAX_HASH_INPUT bytes)",
    },
    Boundary {
        function: "digest-many",
        interface: "qqq:crypto@1.0.0/hashing",
        checks: &[CheckClass::Range, CheckClass::Size],
        guest_controls: "`algorithm` and `inputs`, a **list** — so both list axes apply",
    },
];

/// Every interface name in the table, deduplicated and sorted.
#[must_use]
pub fn interfaces() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = BOUNDARIES.iter().map(|b| b.interface).collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The boundaries that apply `class`.
#[must_use]
pub fn boundaries_checking(class: CheckClass) -> Vec<&'static Boundary> {
    BOUNDARIES.iter().filter(|b| b.applies(class)).collect()
}

/// Extract every function name registered with `func_wrap("…")` from Rust source.
///
/// # Why this strips comments and string literals first
///
/// The first version scanned the raw source and **immediately reported a false
/// boundary**: `host_crypto.rs`'s own doc comments explain the anti-drift test by
/// writing `` `func_wrap("name"` ``, and `name` was duly extracted as a registered
/// host function. That is not a curiosity — a detector that reads prose will keep
/// finding phantom boundaries, and each phantom is a false failure that pressures
/// whoever hits it to weaken the check rather than fix it.
///
/// So the scan works on a comment- and literal-free projection of the source.
/// Whitespace is also normalised, because `rustfmt` lays a `func_wrap` call out
/// differently on different platforms — a lesson `host_crypto.rs` already records
/// for its own anti-drift test, which passed locally and failed on the Windows
/// runner for exactly that reason.
///
/// # What this deliberately does not do
///
/// It does not parse Rust. It is a lexical scan for one call shape, and it is
/// paired with [`every_declared_boundary_names_a_real_function`], which checks the
/// other direction — so the two together fail if either the detector or the table
/// drifts. A full parser would be more precise and would also be a dependency, on
/// the hot path of nothing, to answer a question a 40-line scan answers.
#[must_use]
pub fn registered_names(source: &str) -> Vec<String> {
    // Strip `//`-to-end-of-line comments, and drop string-literal *contents* so a
    // doc example cannot be mistaken for code.
    let mut code = String::with_capacity(source.len());
    for line in source.lines() {
        let trimmed = line.trim_start();
        // Whole-line comments (doc comments are `///` or `//!`).
        if trimmed.starts_with("//") {
            continue;
        }
        // A trailing `//` comment: keep the code before it. This is approximate —
        // a `//` inside a string literal would truncate early — but truncating
        // loses only *code*, which can make this detector miss a registration and
        // therefore fail safe (the other direction's test catches a table that
        // declares a name nothing registers).
        let body = match line.find("//") {
            Some(at) => &line[..at],
            None => line,
        };
        code.push_str(body);
        code.push('\n');
    }

    let squeezed: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let mut out = Vec::new();
    let needle = "func_wrap(\"";
    let mut rest = squeezed.as_str();
    while let Some(at) = rest.find(needle) {
        let after = &rest[at + needle.len()..];
        match after.find('"') {
            Some(end) => out.push(after[..end].to_owned()),
            // An unterminated literal: stop rather than emit a partial name.
            None => break,
        }
        rest = &after[after.find('"').unwrap_or(after.len())..];
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- render_for_diagnostic -------------------------------------------------

    #[test]
    fn control_characters_are_escaped_rather_than_emitted() {
        // This is the log-injection case, stated as the attack: a guest that can
        // put a newline into a diagnostic can forge a second log line.
        let attack = "ok\nERROR disk full\r\nfake";
        let rendered = render_for_diagnostic(attack);
        assert!(
            !rendered.contains('\n') && !rendered.contains('\r'),
            "a raw newline in a diagnostic forges a log line: {rendered:?}"
        );
        assert!(
            rendered.contains("\\n"),
            "the newline must be visible: {rendered:?}"
        );
        assert!(rendered.contains("\\r"));
    }

    #[test]
    fn rendering_truncates_and_says_so() {
        let long = "a".repeat(MAX_ECHO_BYTES * 4);
        let rendered = render_for_diagnostic(&long);
        assert!(
            rendered.ends_with('…'),
            "a truncated echo must be marked as truncated, or a reader cannot tell it \
             was cut: {rendered:?}"
        );
        assert!(rendered.len() <= MAX_ECHO_BYTES + 8);
    }

    #[test]
    fn a_null_byte_is_rendered_visibly() {
        let rendered = render_for_diagnostic("a\0b");
        assert!(!rendered.contains('\0'));
        assert!(rendered.contains("\\u{0}"), "got {rendered:?}");
    }

    #[test]
    fn ordinary_text_passes_through_unchanged() {
        assert_eq!(render_for_diagnostic("orders-2026.csv"), "orders-2026.csv");
        // Including non-ASCII: escaping must not mangle legitimate content.
        assert_eq!(render_for_diagnostic("café"), "café");
    }

    // -- discriminant ----------------------------------------------------------

    #[test]
    fn a_discriminant_in_range_is_accepted_and_one_past_is_not() {
        assert!(discriminant("algorithm", 0, 3).is_accept());
        assert!(discriminant("algorithm", 2, 3).is_accept());
        let v = discriminant("algorithm", 3, 3);
        assert!(v.is_reject(), "3 is not in 0..3");
        let e = v.into_result("algorithm").expect_err("must fail");
        assert!(e.context.iter().any(|(k, _)| k == "argument"));
    }

    #[test]
    fn a_discriminant_at_u32_max_is_rejected_without_panicking() {
        let v = discriminant("algorithm", u32::MAX, 3);
        assert!(v.is_reject());
    }

    #[test]
    fn a_zero_member_set_accepts_nothing() {
        assert!(discriminant("x", 0, 0).is_reject());
    }

    // -- one_of -----------------------------------------------------------------

    #[test]
    fn one_of_accepts_a_member_and_lists_the_options_otherwise() {
        let allowed = ["sha256", "sha512", "blake3"];
        assert!(one_of("algorithm", "sha256", &allowed).is_accept());
        let v = one_of("algorithm", "md5", &allowed);
        match v {
            Verdict::Reject { reason } => {
                assert!(reason.contains("md5"), "the reason must name the value");
                // And it must list what was allowed, so the guest's author can fix it.
                assert!(
                    reason.contains("sha256"),
                    "the reason must list the options"
                );
                assert!(reason.contains("blake3"));
            }
            Verdict::Accept => panic!("md5 is not in the list"),
        }
    }

    #[test]
    fn one_of_escapes_a_hostile_value_in_its_reason() {
        let v = one_of("algorithm", "sha256\nERROR forged", &["sha256"]);
        match v {
            Verdict::Reject { reason } => assert!(
                !reason.contains('\n'),
                "a forged newline must not survive into the diagnostic: {reason:?}"
            ),
            Verdict::Accept => panic!("the value is not a member"),
        }
    }

    // -- size / list_size -------------------------------------------------------

    #[test]
    fn size_accepts_at_the_boundary_and_refuses_past_it() {
        assert!(size("data", 100, 100).is_accept(), "the limit is inclusive");
        assert!(size("data", 101, 100).is_reject());
        assert!(
            size("data", 0, 100).is_accept(),
            "empty is a size question, not a shape one"
        );
    }

    /// **Both list axes are enforced, and each catches what the other misses.**
    #[test]
    fn list_size_enforces_both_element_count_and_total_bytes() {
        // A normal list.
        assert!(list_size("inputs", 10, 1_000).is_accept());

        // Too many elements, tiny in bytes: the shape a byte check misses.
        let v = list_size("inputs", MAX_LIST_ELEMENTS + 1, 1);
        assert!(
            v.is_reject(),
            "element count must be checked independently of bytes"
        );
        match v {
            Verdict::Reject { reason } => assert!(
                reason.contains("element"),
                "the reason must name which axis tripped: {reason}"
            ),
            Verdict::Accept => unreachable!(),
        }

        // Few elements, too many bytes: the shape an element check misses.
        let v = list_size("inputs", 2, MAX_LIST_BYTES + 1);
        assert!(
            v.is_reject(),
            "byte total must be checked independently of count"
        );
        match v {
            Verdict::Reject { reason } => {
                assert!(
                    reason.contains("bytes"),
                    "the reason must name the axis: {reason}"
                );
            }
            Verdict::Accept => unreachable!(),
        }

        // Exactly at both boundaries is accepted, so the limits are inclusive and
        // a legitimate maximum-sized list is not refused by an off-by-one.
        assert!(list_size("inputs", MAX_LIST_ELEMENTS, MAX_LIST_BYTES).is_accept());
    }

    // -- text -------------------------------------------------------------------

    #[test]
    fn text_refuses_empty_oversized_and_control_bearing_values() {
        assert!(text("name", "orders", MAX_IDENTIFIER_BYTES).is_accept());
        assert!(text("name", "", MAX_IDENTIFIER_BYTES).is_reject());
        assert!(text(
            "name",
            &"a".repeat(MAX_IDENTIFIER_BYTES + 1),
            MAX_IDENTIFIER_BYTES
        )
        .is_reject());
        assert!(text("name", "a\0b", MAX_IDENTIFIER_BYTES).is_reject());
        assert!(text("name", "a\nb", MAX_IDENTIFIER_BYTES).is_reject());
        assert!(text("name", "a\tb", MAX_IDENTIFIER_BYTES).is_reject());
    }

    /// **The control that stops `text` becoming a useless check.**
    ///
    /// A validator that refused non-ASCII would break every internationalised
    /// guest. The specific alphabets live in `path_component`, which says so.
    #[test]
    fn text_admits_non_ascii_and_punctuation() {
        for value in ["café", "日本語", "a b", "a/b", "a:b", "a;b", "q=1&r=2"] {
            assert!(
                text("name", value, MAX_IDENTIFIER_BYTES).is_accept(),
                "`{value}` is a legitimate string and must not be refused here; \
                 the restricted alphabets are `path_component`'s job"
            );
        }
    }

    // -- path_shape -------------------------------------------------------------

    /// **The `SEC-011` traversal corpus, as a table.**
    #[test]
    fn path_shape_refuses_every_traversal_shape() {
        let attacks: &[(&str, &str)] = &[
            ("/var/lib/orders/../../../etc/passwd", "the classic"),
            ("../etc/passwd", "relative escape"),
            ("/data/../../etc", "multiple levels"),
            ("..", "bare parent"),
            ("a/..", "trailing parent"),
            ("a/../..", "stacked"),
            ("/data/x/../y", "escape and return"),
            ("foo\\..\\bar", "backslash-separated, Windows-shaped"),
            ("\\..\\", "bare backslash parent"),
            ("/data/..", "parent at the end"),
            ("/data/../", "parent with trailing separator"),
        ];
        for (path, why) in attacks {
            assert!(
                path_shape("path", path).is_reject(),
                "`{path}` ({why}) must be refused"
            );
        }
    }

    /// **The control.** The check must not refuse legitimate paths.
    #[test]
    fn path_shape_admits_legitimate_paths() {
        for path in [
            "/var/lib/orders/data.csv",
            "orders/data.csv",
            "data.csv",
            "./data.csv",
            "/a/b/c",
            // Components that merely contain dots must NOT be refused. This is
            // what separates a component-wise check from a substring search: a
            // naive `contains("..")` refuses every one of these.
            "/data/..hidden",
            "/data/a..b",
            "/data/...",
            "/data/file.tar..gz",
        ] {
            assert!(
                path_shape("path", path).is_accept(),
                "`{path}` is legitimate and must be admitted; a check that refused it \
                 would be a substring search rather than a component check"
            );
        }
    }

    #[test]
    fn path_shape_refuses_empty_oversized_and_control_bearing() {
        assert!(path_shape("path", "").is_reject());
        assert!(path_shape("path", &"a".repeat(MAX_PATH_BYTES + 1)).is_reject());
        assert!(path_shape("path", "a\0b").is_reject());
    }

    /// **The regression guard for `§O-067`.** The prefix implementation would have
    /// admitted every attack above; this asserts the current one does not, by
    /// checking a path whose *prefix* is a legitimate root.
    #[test]
    fn path_shape_does_not_admit_a_traversal_that_starts_inside_a_legitimate_prefix() {
        // The exact input that defeated the old string-prefix containment check.
        assert!(
            path_shape("path", "/var/lib/orders/../../../etc/passwd").is_reject(),
            "a path whose prefix looks legitimate is still a traversal; this is the \
             §O-067 input and it must fail here too"
        );
    }

    // -- path_component ---------------------------------------------------------

    #[test]
    fn path_component_admits_identifiers_and_refuses_structure() {
        for ok in ["orders", "order-2026-01", "a_b.c", "ABC123"] {
            assert!(
                path_component("id", ok).is_accept(),
                "`{ok}` must be admitted"
            );
        }
        for bad in [
            "",        // empty
            ".",       // current directory
            "..",      // parent
            "a/b",     // separator
            "a\\b",    // separator
            "a:b",     // scheme or drive separator
            "a%2e%2e", // percent-encoded traversal
            "a b",     // space
            "café",    // non-ASCII: refused HERE, unlike `text`
            "a\0b", "a\nb", "a?b", "a#b",
        ] {
            assert!(
                path_component("id", bad).is_reject(),
                "`{bad}` must be refused as a path component"
            );
        }
    }

    /// The positive control for the contrast with [`text`]: the same non-ASCII
    /// value is admitted by one and refused by the other, so the two are genuinely
    /// different checks and neither is a copy of the other.
    #[test]
    fn path_component_is_stricter_than_text_on_the_same_input() {
        let value = "café";
        assert!(
            text("name", value, MAX_IDENTIFIER_BYTES).is_accept(),
            "text admits non-ASCII"
        );
        assert!(
            path_component("id", value).is_reject(),
            "path_component refuses it, because a route parameter's alphabet is \
             restricted and that is a property of the position, not of strings"
        );
    }

    // -- range_within -----------------------------------------------------------

    #[test]
    fn range_within_accepts_fitting_ranges_and_refuses_pairs_that_do_not() {
        assert!(range_within("window", 0, 100, 100).is_accept());
        assert!(range_within("window", 50, 50, 100).is_accept());
        assert!(range_within("window", 100, 0, 100).is_accept());

        // **The case two independent range checks would pass.**
        let v = range_within("window", 1000, 1000, 1500);
        assert!(
            v.is_reject(),
            "each operand is valid alone (both <= 1500) but together they reach 2000"
        );
    }

    #[test]
    fn range_within_refuses_an_overflowing_pair_rather_than_wrapping() {
        let v = range_within("window", u64::MAX, 1, u64::MAX);
        assert!(
            v.is_reject(),
            "offset + length overflows u64 and must not wrap"
        );
        match v {
            Verdict::Reject { reason } => assert!(reason.contains("overflow")),
            Verdict::Accept => unreachable!(),
        }
    }

    // -- consistent_length ------------------------------------------------------

    #[test]
    fn consistent_length_admits_agreement_and_refuses_disagreement() {
        assert!(consistent_length("body", 10, 10).is_accept());
        assert!(consistent_length("body", 0, 0).is_accept());

        let short = consistent_length("body", 100, 10);
        assert!(
            short.is_reject(),
            "declared longer than actual: a read past the buffer"
        );
        let long = consistent_length("body", 10, 100);
        assert!(
            long.is_reject(),
            "declared shorter than actual: a silent truncation"
        );
    }

    // -- all --------------------------------------------------------------------

    #[test]
    fn all_returns_the_first_rejection_in_declaration_order() {
        let verdicts = [
            Verdict::Accept,
            Verdict::Reject {
                reason: "first".to_owned(),
            },
            Verdict::Reject {
                reason: "second".to_owned(),
            },
        ];
        match all(&verdicts) {
            Verdict::Reject { reason } => assert_eq!(
                reason, "first",
                "the ordering must be deterministic, or a rejection is not reproducible \
                 from a log line"
            ),
            Verdict::Accept => panic!("there is a rejection in the list"),
        }
    }

    #[test]
    fn all_accepts_an_empty_or_all_accepting_list() {
        assert!(all(&[]).is_accept());
        assert!(all(&[Verdict::Accept, Verdict::Accept]).is_accept());
    }

    // -- the registry -----------------------------------------------------------

    /// **`SEC-011`'s central check: the inventory is complete.**
    ///
    /// Every `func_wrap("name", …)` call site in the crate's host modules must
    /// appear in [`BOUNDARIES`]. Without this, the table is a document; with it,
    /// adding a boundary and forgetting to declare it fails the build.
    #[test]
    fn every_registered_host_function_is_declared_in_the_boundary_table() {
        // The host modules that register guest-callable functions.
        let sources: &[(&str, &str)] = &[
            ("host_clock.rs", include_str!("host_clock.rs")),
            ("host_crypto.rs", include_str!("host_crypto.rs")),
        ];

        let mut registered = Vec::new();
        for (file, source) in sources {
            for name in registered_names(source) {
                registered.push((*file, name));
            }
        }

        assert!(
            !registered.is_empty(),
            "the detection found no registrations at all, so it proves nothing"
        );

        for (file, name) in &registered {
            assert!(
                BOUNDARIES.iter().any(|b| b.function == *name),
                "`{name}` (in {file}) is registered as a guest-callable host function but \
                 is NOT declared in BOUNDARIES. SEC-011 requires validation at every \
                 guest-to-host crossing, and an undeclared boundary is one whose \
                 validation nobody reviewed. Add it to the table with the checks it \
                 applies — even if that list is empty."
            );
        }
    }

    /// The negative control for the detection above.
    #[test]
    fn the_boundary_detection_can_find_a_known_registration() {
        let source = "inst.func_wrap(\n    \"digest\",\n    |s, p| Ok((vec![],)),\n)";
        let squeezed: String = source.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            squeezed.contains("func_wrap(\"digest\""),
            "the whitespace-normalised detection must find a call laid out across lines"
        );
        assert!(
            BOUNDARIES.iter().any(|b| b.function == "digest"),
            "`digest` is registered and must be declared"
        );
        // And a name that is genuinely absent must not be reported.
        assert!(!BOUNDARIES.iter().any(|b| b.function == "nope"));
    }

    /// **A bare function name may legitimately appear in several interfaces.**
    ///
    /// `now` is the clearest case in the corpus: `wall-clock` and
    /// `monotonic-clock` both export a `now`, and `func_wrap` registers the bare
    /// name within each interface instance. So the uniqueness key must be
    /// `(interface, function)` rather than `function` alone — an earlier version
    /// of `the_boundary_table_has_no_duplicates_and_no_empty_justifications`
    /// asserted uniqueness on the function name and would have refused a correct
    /// table. The genuinely required property is that **every registered name
    /// appears at least once**, which the completeness test enforces.
    #[test]
    fn the_same_function_name_may_appear_in_several_interfaces() {
        let now_count = BOUNDARIES.iter().filter(|b| b.function == "now").count();
        assert!(
            now_count >= 2,
            "`now` exists in both clock interfaces and the table must declare both; \
             found {now_count}"
        );
        // But each (interface, function) pair is unique.
        let mut seen = std::collections::BTreeSet::new();
        for b in BOUNDARIES.iter().filter(|b| b.function == "now") {
            assert!(
                seen.insert(b.interface),
                "the same interface declares `now` twice: {}",
                b.interface
            );
        }
    }

    /// The table must not declare a boundary that no longer exists.
    #[test]
    fn every_declared_boundary_names_a_real_function() {
        let sources = concat!(
            include_str!("host_clock.rs"),
            include_str!("host_crypto.rs")
        );
        let registered = registered_names(sources);
        for b in BOUNDARIES {
            assert!(
                registered.iter().any(|n| n == b.function),
                "BOUNDARIES declares `{}` but nothing registers it; a table that lists a \
                 boundary which no longer exists drifts from the code it describes",
                b.function
            );
        }
    }

    /// **The detector must not read prose.** The first version of it did, and
    /// reported `name` as a registered host function because `host_crypto.rs`
    /// writes `` `func_wrap("name"` `` in a doc comment.
    #[test]
    fn the_detector_ignores_comments_and_doc_examples() {
        let source = r#"
/// Whether `source` contains `func_wrap("name"`, ignoring whitespace.
fn registers(source: &str, name: &str) -> bool { false }
// func_wrap("in_a_line_comment", ...)
inst.func_wrap("real", |s, p| Ok(()));
"#;
        let found = registered_names(source);
        assert_eq!(
            found,
            vec!["real".to_owned()],
            "a detector that reads comments invents boundaries; found {found:?}"
        );

        // The same shape laid out across lines must still be found.
        let multiline = "inst\n    .func_wrap(\n        \"digest\",\n        |s, p| Ok(()),\n    )";
        assert_eq!(registered_names(multiline), vec!["digest".to_owned()]);
    }

    /// The detector deduplicates, so a name registered in two interfaces is
    /// reported once — the table's uniqueness is `(interface, function)`.
    #[test]
    fn the_detector_deduplicates_repeated_names() {
        let source = "a.func_wrap(\"now\", f); b.func_wrap(\"now\", g);";
        assert_eq!(registered_names(source), vec!["now".to_owned()]);
    }

    /// The table itself must be internally consistent.
    #[test]
    fn the_boundary_table_has_no_duplicates_and_no_empty_justifications() {
        let mut seen = std::collections::BTreeSet::new();
        for b in BOUNDARIES {
            assert!(
                seen.insert((b.interface, b.function)),
                "`{}` in `{}` is declared twice",
                b.function,
                b.interface
            );
            assert!(
                !b.guest_controls.trim().is_empty(),
                "`{}` must state what the guest controls, even when the answer is \
                 `nothing` — an empty field cannot be distinguished from an unconsidered one",
                b.function
            );
        }
    }

    /// The helper functions agree with the table.
    #[test]
    fn the_query_helpers_agree_with_the_table() {
        let all: Vec<&str> = BOUNDARIES.iter().map(|b| b.function).collect();
        for class in [
            CheckClass::Range,
            CheckClass::Size,
            CheckClass::Shape,
            CheckClass::Consistency,
        ] {
            for b in boundaries_checking(class) {
                assert!(all.contains(&b.function));
            }
        }

        // Size is the most common class, because allocating on the guest's
        // instruction is the boundary risk that appears at nearly every crossing.
        assert!(
            boundaries_checking(CheckClass::Size).len() >= 3,
            "expected several boundaries to bound a size; found {}",
            boundaries_checking(CheckClass::Size).len()
        );

        let ifaces = interfaces();
        assert!(ifaces.contains(&"qqq:crypto@1.0.0/hashing"));
        assert!(ifaces.contains(&"qqq:clock@1.0.0/wall-clock"));
        // Sorted and deduplicated.
        let mut sorted = ifaces.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ifaces, sorted);
    }
}
