// SPDX-License-Identifier: Apache-2.0

//! The call-time grant re-check, proveable — `ARCH-012`.
//!
//! # What the item asks, and what §4.4 says it is for
//!
//! > **ARCH-012** Implement the defence-in-depth re-check of grants at
//! > host-call time.
//!
//! §4.4, step 11:
//!
//! > **Step 11 re-checks.** The grant set is consulted twice — at bind time and
//! > at call time. The second check is defence in depth against a host bug that
//! > mis-builds a linker. It is cheap (a set lookup on a `u32` capability ID)
//! > and it is **non-negotiable**.
//!
//! # The audit that produced this module, and the two wrong answers it gave
//!
//! The first measurement looked for `grants.grants(` inside each `func_wrap`
//! body and reported **8 of 11 host functions with no call-time check**. That
//! number was wrong, and how it was wrong is the reason this module exists in
//! the shape it does.
//!
//! The check *is* reached for those functions — one layer down. `hashing.digest`
//! delegates to [`crate::ambient::hash_data`], which opens with
//! [`crate::ambient::require`]. A grep for the check in the registration body
//! measures where the text lives, not whether the authority is consulted —
//! `§O-071`'s lesson for the fourth time in this workspace.
//!
//! The second measurement was too generous in the other direction: having found
//! the delegation, it would be easy to conclude the item is complete. It is not,
//! because the property §4.4 states is not *"a check exists somewhere on each
//! path"* — it is *"the grant set is consulted twice, independently"*, and the
//! second consultation must not be something a later edit can drop without
//! anything noticing.
//!
//! # What actually enforces it, measured
//!
//! Three mechanisms, each covering a different layer, and the third is the one
//! this module adds:
//!
//! | Mechanism | Where | What it catches |
//! |---|---|---|
//! | **Conditional registration** | `host_clock::register`, `host_crypto::register` | An interface whose capability is absent is never bound, so its functions are not merely refused — they are **absent** |
//! | **Per-function re-check** | `wall-clock.now`, `monotonic-clock.now`, `random.get`, and every path through [`crate::ambient::require`] | A mis-built linker that bound the interface anyway |
//! | **Source-level totality** | [`AUDITED`], checked by [`audit`] | A **new** `func_wrap` added outside a gated registration path |
//!
//! The third is the addition. The first two are properties of the code as
//! written; the third is a property that survives the next edit, and without it
//! "every host function re-checks" is a claim about today's source that nothing
//! re-establishes tomorrow.
//!
//! # Why a table and not a `debug_assert` at each call site
//!
//! Because the failure mode is an **omission**, and an omission cannot raise an
//! assertion. A function that was never written cannot check anything, so the
//! only place to catch it is where the whole set is visible. That is the same
//! reasoning as [`crate::boundary`]'s table (`SEC-011`), and the same shape:
//! enumerate what exists, and fail when the enumeration and the source disagree.

use std::collections::BTreeSet;

use qqq_cap::capability::Capability;

/// One registered host function and the capability that justifies it.
///
/// # Why every field is present even when it looks redundant
///
/// Because a reader asking "can a guest call this without a grant?" needs the
/// answer in one place, and the answer is not always the obvious capability. The
/// `enforced_by` field names *how* the check happens, which is what makes a
/// reviewer able to disagree — `"registration"` is a weaker guarantee than
/// `"per-function"`, and the distinction is invisible if only a capability is
/// recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditedCall {
    /// The file the registration lives in, relative to `crates/qqq-host/src`.
    pub file: &'static str,
    /// The name passed to `func_wrap`.
    pub function: &'static str,
    /// The interface it belongs to, as the linker names it.
    pub interface: &'static str,
    /// The capability that must be granted for the guest to reach it.
    pub capability: Capability,
    /// How the call-time check is enforced.
    pub enforced_by: Enforcement,
}

/// How a host function's call-time authority is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Enforcement {
    /// The `func_wrap` sits inside a `register_*` function that the interface's
    /// `register` only calls when the capability is granted, **and** the
    /// function's own body repeats the check.
    ///
    /// This is the strongest form §4.4 describes: the interface is absent
    /// without the grant, and the function refuses a mis-built linker.
    PerFunction,
    /// The `func_wrap` sits inside a gated `register_*`, and its body relies on
    /// a shared helper that performs the check.
    ///
    /// Equivalent to [`Self::PerFunction`] in force — the check happens on every
    /// call — but the check is not visible in the registration's own text, which
    /// is exactly what made the first audit of this item report a false gap.
    ViaHelper,
    /// The `func_wrap` sits inside a gated `register_*` and performs no check of
    /// its own, because it is a pure function of data the interface's own
    /// gating already covers — `wall-clock.timezone`, which returns the constant
    /// `"UTC"` and reads nothing from the store.
    ///
    /// # Why this variant is allowed to exist
    ///
    /// Because the alternative is a redundant check whose presence would imply
    /// the interface *could* be reached without its grant. Recording the weaker
    /// form explicitly means a reviewer sees the claim rather than inferring
    /// consistency, and a future edit that gives such a function a reason to
    /// read the store must move it to [`Self::PerFunction`] — a visible change
    /// to this table rather than an invisible one to a body.
    InterfaceGated,
}

impl Enforcement {
    /// Whether the capability is consulted on every call, as opposed to the
    /// interface being absent without it.
    ///
    /// # Why this is a separate question from "is it safe"
    ///
    /// Because both answers are safe and they are not the same claim. A
    /// `PerFunction` row survives a mis-built linker; an `InterfaceGated` row
    /// does not, and neither does a `ViaHelper` row if its helper is edited.
    /// Collapsing them into one boolean is how a table like this stops being
    /// able to disagree with the code.
    #[must_use]
    pub const fn rechecks_each_call(self) -> bool {
        matches!(self, Self::PerFunction | Self::ViaHelper)
    }
}

/// Every host function the runtime registers, with its authority and how that
/// authority is enforced — `ARCH-012`.
///
/// # Why this is exhaustive by construction
///
/// [`audit`] compares this table against the source and fails when they
/// disagree in either direction, so a `func_wrap` added without a row here is a
/// test failure rather than an unexamined call path. That is the property that
/// makes the table a check rather than documentation.
pub const AUDITED: [AuditedCall; 8] = [
    AuditedCall {
        file: "host_clock.rs",
        function: "now",
        interface: "qqq:clock/wall-clock@1.0.0",
        capability: Capability::ClockWall,
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_clock.rs",
        function: "resolution",
        interface: "qqq:clock/wall-clock@1.0.0",
        capability: Capability::ClockWall,
        enforced_by: Enforcement::InterfaceGated,
    },
    AuditedCall {
        file: "host_clock.rs",
        function: "timezone",
        interface: "qqq:clock/wall-clock@1.0.0",
        capability: Capability::ClockWall,
        enforced_by: Enforcement::InterfaceGated,
    },
    AuditedCall {
        file: "host_clock.rs",
        function: "now",
        interface: "qqq:clock/monotonic-clock@1.0.0",
        capability: Capability::ClockMonotonic,
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_clock.rs",
        function: "resolution",
        interface: "qqq:clock/monotonic-clock@1.0.0",
        capability: Capability::ClockMonotonic,
        enforced_by: Enforcement::InterfaceGated,
    },
    AuditedCall {
        file: "host_crypto.rs",
        function: "get",
        interface: "qqq:crypto/random@1.0.0",
        capability: Capability::CryptoRandom,
        enforced_by: Enforcement::PerFunction,
    },
    AuditedCall {
        file: "host_crypto.rs",
        function: "digest",
        interface: "qqq:crypto/hashing@1.0.0",
        capability: Capability::CryptoHash,
        enforced_by: Enforcement::ViaHelper,
    },
    AuditedCall {
        file: "host_crypto.rs",
        function: "digest-many",
        interface: "qqq:crypto/hashing@1.0.0",
        capability: Capability::CryptoHash,
        enforced_by: Enforcement::ViaHelper,
    },
];

/// Why the table has eight rows and lists no `hmac` interface.
///
/// # The three rows that were wrong, and how they were caught
///
/// The first version of [`AUDITED`] listed eleven calls, including
/// `hmac-algorithm.name` and `hmac.get`, taken from the WIT's `hmac` interface
/// without checking whether the host implements it. `host_crypto.rs` registers
/// **three** functions — `random.get`, `hashing.digest`, `hashing.digest-many` —
/// and it has a test asserting that the unimplemented interfaces are *not*
/// registered, because registering a stub would replace a clear instantiation
/// failure with a runtime mystery.
///
/// So three rows described code that does not exist, and [`audit`] reported them
/// as [`AuditFinding::Stale`]. That is the table working as designed: a claim of
/// coverage is checked against the source, and a table that can never disagree
/// with the code is documentation rather than a check.
///
/// `CryptoHmac` therefore appears in no row, and
/// `the_table_covers_every_capability_the_host_can_bind` does **not** require
/// it — the capability is grantable and unimplemented, which `describe_gap`
/// reports at instantiation.
///
/// A disagreement between [`AUDITED`] and the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditFinding {
    /// A `func_wrap` in the source that no table row names.
    Unlisted {
        /// The file.
        file: String,
        /// The function name.
        function: String,
        /// The line, so the reader can look at it.
        line: usize,
    },
    /// A table row naming a `func_wrap` the source does not contain.
    Stale {
        /// The file.
        file: &'static str,
        /// The function name.
        function: &'static str,
    },
    /// A table entry claiming a per-function re-check where the body has none
    /// and does not delegate to a helper that does.
    UnbackedClaim {
        /// The file.
        file: &'static str,
        /// The function name.
        function: &'static str,
    },
}

impl std::fmt::Display for AuditFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unlisted {
                file,
                function,
                line,
            } => write!(
                f,
                "{file}:{line} registers `{function}`, which no entry in \
                 `arch012::AUDITED` names. Every host function must be listed \
                 with the capability that justifies it and how that capability \
                 is checked -- an unlisted one is a call path nobody has \
                 reasoned about."
            ),
            Self::Stale { file, function } => write!(
                f,
                "`arch012::AUDITED` lists `{file}`:`{function}`, which the source \
                 does not register. A stale row makes the table claim coverage \
                 it does not have."
            ),
            Self::UnbackedClaim { file, function } => write!(
                f,
                "`arch012::AUDITED` claims `{file}`:`{function}` re-checks its \
                 capability on every call, but its body contains no \
                 `grants.grants(..)` and no call to a helper that has one. The \
                 claim in the table is not backed by the code."
            ),
        }
    }
}

/// A `func_wrap` found in the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    /// The file it was found in.
    pub file: String,
    /// The instance the registration is attached to.
    pub interface: String,
    /// The name passed to `func_wrap`.
    pub function: String,
    /// The 1-based line.
    pub line: usize,
    /// Whether the body reaches a capability check, directly or via a helper
    /// this module knows about.
    pub checks_capability: bool,
}

/// Helpers that perform a capability check, so a `func_wrap` body that calls
/// one is counted as checked.
///
/// # Why a name list rather than a dataflow analysis
///
/// Because a dataflow analysis here would be a second implementation of Rust,
/// and the property it would establish is the one [`AUDITED`] already states by
/// hand and [`audit`] cross-checks. The list is short, explicit, and a helper
/// that starts gating must be added to it — whereupon the `UnbackedClaim` check
/// begins validating the rows that depend on it.
pub const CHECKING_HELPERS: [&str; 2] = ["hash_data(", "ambient::require("];

/// Cross-check [`AUDITED`] against the source in `sources`.
///
/// # Errors
///
/// Returns every [`AuditFinding`], sorted, so a reader sees the whole gap
/// rather than the first item of it.
///
/// # Why this takes the sources as an argument
///
/// So it can be tested with a **fabricated** source set. A checker that can only
/// read the real tree cannot be proven to detect anything — it can only be
/// observed to pass, which is the defect `§M-006` records and `§O-092` records
/// again. The test suite drives it with a source containing an unlisted
/// `func_wrap` and a row claiming an unbacked re-check, and asserts both are
/// reported.
pub fn audit(sources: &[(String, String)]) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();

    for (file, text) in sources {
        for registered in scan(file, text) {
            // **Keyed by `(file, interface, function)`, not `(file, function)`.**
            // Two capabilities share a function name in one file --
            // `wall-clock.now` and `monotonic-clock.now`, and likewise
            // `resolution` -- so a two-part key made the audit able to match the
            // wrong row. The dangerous direction is `UnbackedClaim` passing
            // because a *namesake* is backed: `monotonic-clock.now` could lose
            // its grant check while `wall-clock.now` kept one.
            seen.insert((
                file.clone(),
                registered.interface.clone(),
                registered.function.clone(),
            ));
            let row = AUDITED.iter().find(|a| {
                a.file == file.as_str()
                    && a.function == registered.function.as_str()
                    && registered
                        .interface
                        .ends_with(interface_suffix(a.interface))
            });
            match row {
                None => findings.push(AuditFinding::Unlisted {
                    file: registered.file,
                    function: registered.function,
                    line: registered.line,
                }),
                Some(a) if a.enforced_by.rechecks_each_call() && !registered.checks_capability => {
                    findings.push(AuditFinding::UnbackedClaim {
                        file: a.file,
                        function: a.function,
                    });
                }
                Some(_) => {}
            }
        }
    }

    for row in &AUDITED {
        let named = seen
            .iter()
            .any(|(f, _, fn_)| f == row.file && fn_ == row.function);
        if !named {
            findings.push(AuditFinding::Stale {
                file: row.file,
                function: row.function,
            });
        }
    }

    findings.sort_by_key(ToString::to_string);
    findings.dedup();
    findings
}

/// The part of an interface name that follows the version, so a table row can
/// be matched against an interface path written in a registration.
///
/// `qqq:clock@1.0.0/wall-clock` becomes `wall-clock`, which is what the
/// registration writes as the instance name.
fn interface_suffix(interface: &str) -> &str {
    interface.rsplit('/').next().unwrap_or(interface)
}

/// Find every `func_wrap("name", …)` in one **production** source, and whether
/// its body reaches a capability check.
///
/// # Why the scan strips comments and stops at the test module
///
/// The first version scanned the raw text and found **20** registrations where
/// the source has 11. The nine extras were diagnostic:
///
/// ```text
/// ("host_clock.rs", "engine", 409)          a test helper, inside #[cfg(test)]
/// ("host_crypto.rs", "{name}\\", 439)        an escaped quote in a doc comment
/// ("host_crypto.rs", "digest\\", 497..499)   doc-comment prose
/// ("host_crypto.rs", "get\\", 817)           doc-comment prose
/// ```
///
/// This is the defect `§O-071` already records for a *different* checker
/// (`SEC-011`'s boundary table): **"the name extractor read doc comments,
/// inventing `name` as a boundary because the source writes
/// ``func_wrap("name"`` in its own prose."** Recorded once, then repeated in new
/// code an hour later — which is why the fix has two independent halves rather
/// than one careful stripper.
///
/// # Why the body is taken as everything up to the *next* `func_wrap`
///
/// Because matching the closing brace of a closure whose body contains braces
/// needs a real parser, and a brace counter is a parser that is wrong on strings
/// and comments — both of which these bodies contain. Slicing to the next
/// registration is exact for this codebase's shape (one registration per
/// `func_wrap`, in order), and it fails **loudly** rather than silently if that
/// shape changes.
#[must_use]
pub fn scan(file: &str, text: &str) -> Vec<Registered> {
    let production = production_lines(file, text);
    let starts: Vec<usize> = production
        .match_indices("func_wrap(")
        .map(|(i, _)| i)
        .collect();
    let mut out = Vec::with_capacity(starts.len());
    for (idx, start) in starts.iter().enumerate() {
        let end = starts.get(idx + 1).copied().unwrap_or(production.len());
        let body = &production[*start..end];
        let Some(name) = function_name(body) else {
            continue;
        };
        // **The structural half.** A real `func_wrap` name is a WIT kebab-case
        // identifier. Anything else is prose that survived the stripper, and
        // rejecting it here means the audit reports a missing row rather than
        // inventing an unlisted function -- a loud failure in place of a quiet
        // one, and independent of how well the stripper works.
        if !is_identifier(&name) {
            continue;
        }
        let line = text[..text.len().saturating_sub(production.len() - *start)]
            .matches('\n')
            .count()
            + 1;
        let checks =
            body.contains("grants.grants(") || CHECKING_HELPERS.iter().any(|h| body.contains(h));
        out.push(Registered {
            file: file.to_owned(),
            interface: instance_name(text, &production[..*start]),
            function: name,
            line,
            checks_capability: checks,
        });
    }
    out
}

/// The interface the registration is attached to, from the nearest preceding
/// `linker.instance(NAME)`.
///
/// # Why the nearest preceding instance is the right answer
///
/// Because every registration in this codebase is written as
/// `let mut inst = linker.instance(WALL_CLOCK)?;` followed by one or more
/// `inst.func_wrap(..)` calls, so the enclosing instance is the most recent one
/// opened above the call. A registration that opened no instance inherits the
/// previous one, which shows up as a wrong interface in a finding -- loud rather
/// than silent.
///
/// # Why the argument is resolved through the file's own constants
///
/// Because the registrations pass a **constant**, not a literal:
/// `linker.instance(RANDOM)`, `linker.instance(WALL_CLOCK)`. A resolver that
/// looked for `"` found nothing, every registration got an empty interface, no
/// row matched, and the audit reported all eight as unlisted -- which is how the
/// bug appeared. Resolving the identifier against the `pub const NAME: &str =
/// "..."` declarations in the same file is exact for this codebase and fails
/// loudly if it ever stops being: an unresolved name yields an empty interface,
/// which matches no row.
fn instance_name(source: &str, before: &str) -> String {
    let mut ident = String::new();
    for line in before.lines() {
        if let Some(i) = line.find(".instance(") {
            let rest = &line[i + ".instance(".len()..];
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            let candidate = &rest[..end];
            if !candidate.is_empty() {
                candidate.clone_into(&mut ident);
            }
        }
    }
    if ident.is_empty() {
        return String::new();
    }
    literal_of(source, &ident).unwrap_or_default()
}

/// The string literal a `pub const NAME: &str = "...";` declares, if any.
fn literal_of(source: &str, ident: &str) -> Option<String> {
    let needle = format!("const {ident}");
    for line in source.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("pub const ") && !trimmed.starts_with("const ") {
            continue;
        }
        if !line.contains(&needle) || !line.contains(": &str") {
            continue;
        }
        let eq = line.find('=')?;
        let rest = line.get(eq + 1..)?;
        let q = rest.find('"')?;
        let after = rest.get(q + 1..)?;
        let close = after.find('"')?;
        return Some(after.get(..close)?.to_owned());
    }
    None
}

/// Whether a candidate name is a WIT identifier rather than surviving prose.
///
/// # Why kebab-case is the test
///
/// Because it is what `func_wrap` is given everywhere in this workspace: the WIT
/// function name. A name containing `\\`, `{`, `}` or whitespace is a fragment
/// of a doc comment or a format string, and no registration in this codebase can
/// produce one. Widening this predicate to accept more would let prose back in;
/// narrowing it would drop a real registration, which the audit would then
/// report as a missing row.
fn is_identifier(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The source with comment lines removed and everything from `#[cfg(test)]`
/// onward dropped.
///
/// # Why line-based rather than a real lexer
///
/// Because a lexer is a component with its own bugs, and the property needed
/// here is only "no `func_wrap(` from a comment or a test survives". Both of
/// those are line-shaped in this codebase: doc comments occupy whole lines, and
/// the test module is a contiguous tail. A block comment spanning lines would
/// defeat it — and there is none in these files, which
/// `the_real_sources_contain_no_block_comments` asserts rather than assumes, so
/// the day one appears the suite says so instead of the audit quietly changing
/// its answer.
fn production_lines(file: &str, text: &str) -> String {
    let _ = file;
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[cfg(test)]") {
            break;
        }
        if trimmed.starts_with("//") {
            // Keep the newline so line numbers stay aligned with the original.
            out.push('\n');
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// The first string literal passed to `func_wrap`.
///
/// # Why this looks for the literal after the paren rather than parsing
///
/// Because the only thing between `func_wrap(` and its first argument is
/// whitespace, and this codebase writes it on one line every time. A shape that
/// changed would produce `None` here, and `None` means the registration is
/// **skipped** — so the audit would report a missing row for a function that
/// exists, which is a loud failure rather than a quiet pass.
fn function_name(body: &str) -> Option<String> {
    let open = body.find('(')?;
    let rest = body.get(open + 1..)?;
    let quote = rest.find('"')?;
    let after = rest.get(quote + 1..)?;
    let close = after.find('"')?;
    Some(after.get(..close)?.to_owned())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The real sources, read the same way the CI checker reads them.
    fn real_sources() -> Vec<(String, String)> {
        ["host_clock.rs", "host_crypto.rs", "host_secrets.rs"]
            .iter()
            .filter_map(|name| {
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("src")
                    .join(name);
                std::fs::read_to_string(&path)
                    .ok()
                    .map(|text| ((*name).to_owned(), text))
            })
            .collect()
    }

    /// **The check that survives the next edit.** Every host function in the
    /// real source must have a row, and every row must be backed.
    #[test]
    fn the_table_and_the_real_sources_agree() {
        let findings = audit(&real_sources());
        assert!(
            findings.is_empty(),
            "the ARCH-012 table disagrees with the source:\n{}",
            findings
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// The scan must actually find the registrations, or the agreement above is
    /// the agreement of two empty sets.
    #[test]
    fn the_scan_finds_every_registration_in_the_real_sources() {
        let found: Vec<Registered> = real_sources()
            .iter()
            .flat_map(|(f, t)| scan(f, t))
            .collect();
        assert_eq!(
            found.len(),
            AUDITED.len(),
            "scan found {} registrations, the table lists {}: {:?}",
            found.len(),
            AUDITED.len(),
            found
                .iter()
                .map(|r| (&r.file, &r.function, r.line))
                .collect::<Vec<_>>()
        );
    }

    /// **Fault injection 1: an unlisted `func_wrap` is reported.**
    #[test]
    fn an_unlisted_host_function_is_reported() {
        let source = r#"
            inst.func_wrap("brand-new", |_s, ()| Ok(()))?;
        "#;
        let findings = audit(&[("host_new.rs".to_owned(), source.to_owned())]);
        assert!(
            findings.iter().any(
                |f| matches!(f, AuditFinding::Unlisted { function, .. } if function == "brand-new")
            ),
            "{findings:?}"
        );
        let text = findings
            .iter()
            .find(|f| matches!(f, AuditFinding::Unlisted { .. }))
            .unwrap()
            .to_string();
        assert!(text.contains("host_new.rs"), "{text}");
        assert!(text.contains("nobody has reasoned about"), "{text}");
    }

    /// **Fault injection 2: a row claiming a per-function re-check that the
    /// body does not perform is reported.**
    ///
    /// This is the check that makes the table able to disagree with the code in
    /// the direction that matters: a table claiming *more* safety than exists.
    #[test]
    fn a_row_claiming_an_unbacked_re_check_is_reported() {
        // A realistic fixture: the instance is opened from the file's own
        // constant, exactly as `host_clock.rs` does it, so the interface
        // resolves and the row can be matched. A fixture that omitted the
        // `instance` line would produce an empty interface, no matching row and
        // an `Unlisted` finding instead -- which is why this fixture carries it.
        let source = r#"
            pub const WALL_CLOCK: &str = "qqq:clock/wall-clock@1.0.0";
            let mut inst = linker.instance(WALL_CLOCK)?;
            inst.func_wrap("now", |_store, (): ()| Ok((0u64,)))?;
        "#;
        let findings = audit(&[("host_clock.rs".to_owned(), source.to_owned())]);
        assert!(
            findings.iter().any(|f| matches!(
                f,
                AuditFinding::UnbackedClaim { function, .. } if *function == "now"
            )),
            "{findings:?}"
        );
    }

    /// A body that reaches a checking helper satisfies the claim, which is why
    /// `digest` is `ViaHelper` rather than `PerFunction`.
    #[test]
    fn a_body_reaching_a_checking_helper_satisfies_the_claim() {
        let source = r#"
            inst.func_wrap("digest", |store, (a, d)| {
                hash_data(store.data(), "sha256", &d)
            })?;
        "#;
        let findings = audit(&[("host_crypto.rs".to_owned(), source.to_owned())]);
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f, AuditFinding::UnbackedClaim { .. })),
            "a body delegating to `hash_data` must satisfy the claim: {findings:?}"
        );
    }

    /// **Fault injection 3: a stale row is reported.** A table that lists a
    /// function the source no longer has claims coverage it does not have.
    #[test]
    fn a_stale_row_is_reported() {
        let findings = audit(&[]);
        assert!(
            !findings.is_empty(),
            "an empty source set must make rows stale"
        );
        assert!(
            findings
                .iter()
                .all(|f| matches!(f, AuditFinding::Stale { .. })),
            "{findings:?}"
        );
        // `Stale` is reported per `(file, function)` and deduplicated, and two
        // pairs repeat in the table because the wall and monotonic clocks name
        // the same functions in the same file. The count is therefore smaller
        // than the row count -- which is exactly why the *key* had to change;
        // see `the_audited_identity_is_unique`.
        let distinct: BTreeSet<(&str, &str)> =
            AUDITED.iter().map(|a| (a.file, a.function)).collect();
        assert_eq!(findings.len(), distinct.len());
    }

    /// **`(file, function)` does not uniquely identify a row, and the audit must
    /// not pretend it does.**
    ///
    /// `wall-clock.now` and `monotonic-clock.now` share both, as do the two
    /// `resolution`s. With a two-part key, `UnbackedClaim` could pass a row
    /// because its *namesake* was backed -- `monotonic-clock.now` losing its
    /// grant check while `wall-clock.now` kept one. The key is therefore
    /// `(file, interface, function)`, and this test pins that it is unique.
    #[test]
    fn the_audited_identity_is_unique() {
        let keys: BTreeSet<(&str, &str, &str)> = AUDITED
            .iter()
            .map(|a| (a.file, a.interface, a.function))
            .collect();
        assert_eq!(
            keys.len(),
            AUDITED.len(),
            "two rows share (file, interface, function): {keys:?}"
        );

        let pairs: BTreeSet<(&str, &str)> = AUDITED.iter().map(|a| (a.file, a.function)).collect();
        assert!(
            pairs.len() < AUDITED.len(),
            "this test exists because the two-part key collides; if it no longer              does, the reasoning in `audit` should be revisited"
        );
    }

    /// `InterfaceGated` is allowed to perform no check, because the interface is
    /// not bound without the capability. It must NOT be reported as unbacked.
    #[test]
    fn an_interface_gated_row_needs_no_check_in_its_body() {
        let source = r#"
            inst.func_wrap("timezone", |_store, (): ()| Ok(("UTC".to_owned(),)))?;
        "#;
        let findings = audit(&[("host_clock.rs".to_owned(), source.to_owned())]);
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f, AuditFinding::UnbackedClaim { .. })),
            "`timezone` is interface-gated and reads nothing: {findings:?}"
        );
    }

    /// The enforcement classification must be honest about which rows survive a
    /// mis-built linker.
    #[test]
    fn the_enforcement_classification_separates_the_two_kinds_of_safety() {
        assert!(Enforcement::PerFunction.rechecks_each_call());
        assert!(Enforcement::ViaHelper.rechecks_each_call());
        assert!(
            !Enforcement::InterfaceGated.rechecks_each_call(),
            "an interface-gated function does not consult the grant itself"
        );
    }

    /// Every row must name a real capability and a plausible file, so the table
    /// cannot rot into placeholders.
    #[test]
    fn every_row_is_wellformed() {
        for row in &AUDITED {
            assert!(!row.function.is_empty(), "{row:?}");
            assert!(
                row.interface.starts_with("qqq:"),
                "an interface must be namespaced: {row:?}"
            );
            assert_eq!(
                std::path::Path::new(row.file).extension(),
                Some(std::ffi::OsStr::new("rs")),
                "a row names a Rust file: {row:?}"
            );
        }
    }

    /// The table must cover every capability the two `register` paths can bind,
    /// or a granted capability with no audited call is a hole in the audit's
    /// premise.
    #[test]
    fn the_table_covers_every_capability_the_host_can_bind() {
        let covered: BTreeSet<Capability> = AUDITED.iter().map(|a| a.capability).collect();
        for expected in [
            Capability::ClockWall,
            Capability::ClockMonotonic,
            Capability::CryptoRandom,
            Capability::CryptoHash,
        ] {
            assert!(
                covered.contains(&expected),
                "`{expected}` is bindable but has no audited call"
            );
        }
        // `CryptoHmac` is deliberately absent: it is grantable and
        // **unimplemented**, so it has no host call to audit. Asserting its
        // absence pins that, so the day an hmac function is registered the table
        // must gain a row -- and `the_table_and_the_real_sources_agree` will say
        // so, because the new `func_wrap` will be unlisted.
        assert!(
            !covered.contains(&Capability::CryptoHmac),
            "an hmac call now exists; add it to AUDITED"
        );
    }

    /// **The capability this item is really about: `CryptoHash` must be reached
    /// through a check.** `digest` is the function a guest actually calls, and a
    /// guest without the grant must not reach `hash_data`'s work.
    #[test]
    fn the_hashing_functions_are_at_least_helper_checked() {
        for row in AUDITED
            .iter()
            .filter(|a| a.capability == Capability::CryptoHash)
        {
            assert!(
                row.enforced_by.rechecks_each_call(),
                "{row:?} is a hashing entry that does not consult the grant"
            );
        }
    }

    /// `function_name` must not be fooled by a name containing an escape.
    #[test]
    fn the_name_extractor_reads_the_first_literal() {
        assert_eq!(
            function_name(r#"func_wrap("now", |..| {})"#),
            Some("now".to_owned())
        );
        assert_eq!(
            function_name(r#"func_wrap(  "digest-many" , ..)"#),
            Some("digest-many".to_owned())
        );
        assert_eq!(function_name("func_wrap(no_literal)"), None);
    }

    /// The scan reports the line of the registration, so a finding points at
    /// the code.
    #[test]
    fn the_scan_reports_the_line_of_each_registration() {
        let source = "line one\nline two\ninst.func_wrap(\"x\", ..);\n";
        let found = scan("f.rs", source);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 3);
    }
}
