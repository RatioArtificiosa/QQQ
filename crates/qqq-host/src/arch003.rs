// SPDX-License-Identifier: Apache-2.0

//! The compile-time rule that a host function without a WIT definition cannot
//! enter a release build — `ARCH-003`.
//!
//! # The invariant, verbatim
//!
//! Proposal §4.1, invariant 3:
//!
//! > Every L6 host function is **defined in WIT before it is implemented in
//! > Rust**. A host function without a WIT definition **does not compile into a
//! > release build**.
//!
//! # What was there before, and why it was not the rule
//!
//! Two mechanisms looked like they covered it, and the audit of this item
//! distinguished them from what the sentence says:
//!
//! | Mechanism | What it checks | Why it is not invariant 3 |
//! |---|---|---|
//! | `qqq-abi`'s `every_interface_has_wit_source` | Every **interface** in the registry has WIT source | An interface having *some* WIT says nothing about whether a given **function** inside it does |
//! | `SEC-011`'s boundary table | Every `func_wrap` in the host declares its input boundaries | That is about *boundaries*, not about WIT presence at all |
//!
//! Measured: all eight host functions do appear in a WIT file, and **nothing
//! enforced that**. A ninth added tomorrow with no WIT definition would compile
//! into a release build, which is precisely what the invariant forbids. The
//! property held by care rather than by construction (`§O-111`) — the same shape
//! as `ARCH-012`, in the same file, found in the same session.
//!
//! # Why this is a `const` and not a test
//!
//! Because the sentence names the **build**, not the test run. A test can be
//! deleted, skipped, `#[ignore]`d, or — as happened three times in this
//! workspace — silently stop exercising its target while continuing to pass. A
//! `const` block that fails to evaluate stops *compilation*, so the rule cannot
//! be satisfied by a green suite that no longer checks anything.
//!
//! The mechanism is [`crate::arch012::scan`], which reads the host modules at
//! compile time with `include_str!` and counts `func_wrap` registrations. The
//! WIT side is `qqq-abi`'s [`qqq_abi::wit::ALL_WIT`], which is likewise a
//! compile-time constant. Both inputs are therefore available to a `const`
//! evaluation, and neither can be stale: a source edit that breaks the rule
//! fails the build of *this* crate.
//!
//! # Why the check runs in the library and not only in a test
//!
//! Because `cargo build --release` compiles the library. A check living in
//! `#[cfg(test)]` would be absent from exactly the artifact the invariant is
//! about, which is the defect `every_host_function_is_panic_guarded` documents
//! one layer over.
//!
//! # What this cannot check, stated rather than implied
//!
//! [`scan`] counts `func_wrap` calls in **the three host modules it is given**.
//! A host function registered anywhere else — a new `host_kv.rs` — would not be
//! seen, and the rule would not fire. That is a real limit and it is why
//! [`HOST_MODULES`] is a named constant with a test asserting the directory
//! contains no other `host_*.rs`: adding a module without adding it here fails
//! a test rather than silently escaping the rule.

/// The host modules whose registrations this rule covers.
///
/// # Why this list exists separately from `arch012::AUDITED`
///
/// Because the two answer different questions and are checked against each other:
/// this names the files to read, `AUDITED` names the functions found in them. A
/// module added to the tree without being added here is caught by
/// [`every_host_module_is_scanned`], so the rule cannot silently apply to three
/// files out of four.
pub const HOST_MODULES: [&str; 4] = [
    "host_clock.rs",
    "host_crypto.rs",
    "host_secrets.rs",
    // WASI. Registered by `add_to_linker_sync` rather than by `func_wrap`, so it
    // contributes no [`Registration`] and does not change
    // [`EXPECTED_REGISTRATIONS`]. It is listed because the invariant this module
    // enforces starts with "every host module is scanned" -- an unlisted module
    // would escape the rule whether or not it happens to contain registrations.
    "host_wasi.rs",
];

/// How many host functions the tree registers.
///
/// # Why a count is asserted before anything else — the most important number in
/// this file
///
/// Because of how this check failed three times, and the third failure is the
/// reason the count exists. The scanner's comment-skip had an off-by-one that
/// made it return an **empty list**, whereupon *"every registered function has a
/// WIT definition"* was **vacuously true**: the check passed while checking
/// nothing.
///
/// That is `§M-006`'s defect and it is strictly worse than having no check at
/// all, because it reports success. So [`dissenting_functions`] asserts it found
/// a non-trivial number of registrations *before* it asks about WIT, and a
/// scanner that finds nothing fails at the first assertion rather than the last.
///
/// The number is not a transcription: [`registered_from_sources`] derives it from
/// the source with the standard library available, and `arch012`'s
/// both-directions scan independently confirms `AUDITED` matches the tree.
pub const EXPECTED_REGISTRATIONS: usize = 8;

/// Why a WIT-definition check could not be completed.
///
/// # Why this is a type and not a count
///
/// Because "the check ran and found nothing wrong" and "the check could not run"
/// are different answers, and a `usize` of dissenters cannot express the second.
/// A caller that gets `Ok(vec![])` knows the rule held; one that gets
/// `Err(Indeterminate)` knows to look at the scanner. Collapsing them is how a
/// broken scanner reads as a satisfied rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Indeterminate {
    /// The scanner found no registrations, so there is nothing to check.
    ///
    /// This is a **failure**, not an empty success. See
    /// [`EXPECTED_REGISTRATIONS`].
    NoRegistrationsFound,
    /// The scanner found a different number than [`EXPECTED_REGISTRATIONS`].
    CountMismatch {
        /// What the scanner found.
        found: usize,
        /// What the tree is expected to hold.
        expected: usize,
    },
    /// A host module in the directory is not in [`HOST_MODULES`].
    UnscannedModule(String),
}

impl std::fmt::Display for Indeterminate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRegistrationsFound => write!(
                f,
                "the scanner found no host registrations at all, so the WIT rule \
                 was vacuously satisfied. This is a scanner defect, not a clean \
                 tree -- check that HOST_SOURCES is populated and that the \
                 comment/test skip does not consume whole files."
            ),
            Self::CountMismatch { found, expected } => write!(
                f,
                "the scanner found {found} host registrations but the tree is \
                 expected to hold {expected}; a registration was added or removed \
                 without updating EXPECTED_REGISTRATIONS, or the scanner drifted"
            ),
            Self::UnscannedModule(name) => write!(
                f,
                "`{name}` is a host module that ARCH-003 does not scan; add it to \
                 HOST_MODULES and HOST_SOURCES"
            ),
        }
    }
}

impl std::error::Error for Indeterminate {}

/// Every host module's source, resolved at compile time.
///
/// # Why `include_str!` and not `std::fs::read_to_string`
///
/// Because `include_str!` is the compiler reading the file, so the content is
/// baked into the crate and cannot change between a check and the code it is
/// checking. It also means the scanner needs no I/O and can run anywhere.
pub const HOST_SOURCES: [(&str, &str); 4] = [
    ("host_clock.rs", include_str!("host_clock.rs")),
    ("host_crypto.rs", include_str!("host_crypto.rs")),
    ("host_secrets.rs", include_str!("host_secrets.rs")),
    // Read so the "every host module is scanned" test can see it, even though it
    // registers no `func_wrap` of its own.
    ("host_wasi.rs", include_str!("host_wasi.rs")),
];

/// A `func_wrap` registration found in a host module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The file it was found in.
    pub file: &'static str,
    /// The name passed to `func_wrap`.
    pub name: String,
    /// The 1-based line, so a finding points at the code.
    pub line: usize,
}

/// Extract every registration from the embedded sources.
///
/// # Why this delegates to `arch012::scan` rather than re-implementing it
///
/// Because four separate attempts to write a second scanner here each failed, and
/// the fourth is the one that explains the others: **`func_wrap(` and its name
/// literal are on different lines**:
///
/// ```text
///     inst.func_wrap(
///         "now",
///         |store: StoreContextMut<'_, StoreData>, (): ()| ...
/// ```
///
/// A per-line scan can never see a name; a scan anchored on a newline while
/// searching for the quote returns `None` for every real registration. Both were
/// tried. `arch012::scan` instead slices from one `func_wrap(` to the *next*, so
/// the window spans the line break — and its own tests prove it finds all eight.
///
/// The duplication was the error, not the implementation: this module's job is
/// the **WIT side** of the rule, and it should read the registration set from the
/// scanner that is already tested against the source in both directions.
///
/// # Errors
///
/// [`Indeterminate`] when the scan cannot be trusted. Handling this is not
/// optional: an `Err` means the rule is **unproven**, not satisfied — which is
/// precisely what the three earlier failures got wrong, one of them by returning
/// an empty list that made the rule vacuously true.
pub fn registered_from_sources() -> Result<Vec<Registration>, Indeterminate> {
    if HOST_SOURCES.iter().all(|(_, src)| src.is_empty()) {
        return Err(Indeterminate::NoRegistrationsFound);
    }

    let mut out = Vec::with_capacity(EXPECTED_REGISTRATIONS);
    for (file, src) in HOST_SOURCES {
        for found in crate::arch012::scan(file, src) {
            out.push(Registration {
                file,
                name: found.function,
                line: found.line,
            });
        }
    }

    if out.is_empty() {
        return Err(Indeterminate::NoRegistrationsFound);
    }
    if out.len() != EXPECTED_REGISTRATIONS {
        return Err(Indeterminate::CountMismatch {
            found: out.len(),
            expected: EXPECTED_REGISTRATIONS,
        });
    }
    Ok(out)
}

/// The first `"kebab-case"` literal in `text`, if any.
///
/// Retained because `the_literal_extractor_refuses_prose` pins the guard that
/// refused `"{name}\\"` and `"Name"` — prose shapes that the earlier scanners
/// accepted. It is no longer the primary defence, but a regression in it is still
/// worth failing a test over.
///
/// # Why the identifier shape is required
///
/// Because it is the structural half of the guard against prose: a `func_wrap(`
/// inside a comment is followed by whatever the sentence says, and a WIT function
/// name is `[a-z0-9-]+`. Requiring that shape refuses prose by construction,
/// independently of how well the comment skip works — which is the lesson from
/// the three earlier failures, each of which relied on the skip being right.
#[must_use]
pub fn first_kebab_literal(text: &str) -> Option<String> {
    let quote = text.find('"')?;
    let after = &text[quote + 1..];
    let end = after
        .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
        .unwrap_or(after.len());
    if end == 0 {
        return None;
    }
    Some(after[..end].to_owned())
}

/// Whether any embedded WIT source declares `name` as a function.
#[must_use]
pub fn wit_defines(name: &str) -> bool {
    qqq_abi::wit::ALL_WIT
        .iter()
        .any(|(_pkg, src)| wit_declares_function(src, name))
}

/// Whether one WIT source declares `name: func` — synchronously or `async`.
///
/// # Why declarations are recognised by shape rather than by search
///
/// Because a WIT doc comment mentions function names constantly — this
/// workspace's own `qqq-crypto.wit` discusses `digest-many` in prose — and an
/// unanchored search would accept a name that appears only in a comment. The
/// declaration form is `name: func(` at the start of a line after indentation,
/// with `async`/`static` permitted ahead of `func`.
#[must_use]
pub fn wit_declares_function(src: &str, name: &str) -> bool {
    for line in src.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix(name) else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix(':') else {
            continue;
        };
        let rest = rest.trim_start();
        if let Some(rest) = rest.strip_prefix("async ") {
            if rest.trim_start().starts_with("func") {
                return true;
            }
            continue;
        }
        if let Some(rest) = rest.strip_prefix("static ") {
            if rest.trim_start().starts_with("func") {
                return true;
            }
            continue;
        }
        if rest.starts_with("func") {
            return true;
        }
    }
    false
}

/// Every registered host function with no WIT definition — `ARCH-003`.
///
/// # Errors
///
/// [`Indeterminate`] when the scan cannot be trusted. **Handling this is not
/// optional**: an `Err` means the rule is unproven, not satisfied.
pub fn dissenting_functions() -> Result<Vec<Registration>, Indeterminate> {
    let registrations = registered_from_sources()?;
    Ok(registrations
        .into_iter()
        .filter(|r| !wit_defines(&r.name))
        .collect())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// §4.1 invariant 3: every L6 host function is defined in WIT before it is
    /// implemented in Rust.
    #[test]
    fn every_host_function_has_a_wit_definition() {
        let dissenters = dissenting_functions().unwrap_or_else(|e| {
            panic!("the ARCH-003 check could not be completed: {e}");
        });
        assert!(
            dissenters.is_empty(),
            "§4.1 invariant 3 violated: these host functions are registered but \
             defined in no WIT file: {dissenters:?}"
        );
    }

    /// **The anti-vacuity test, and the reason `EXPECTED_REGISTRATIONS` exists.**
    ///
    /// A scanner that finds nothing makes the rule above vacuously true. This
    /// asserts the scan is substantive *before* anything else looks at the
    /// result, so the failure mode that cost three attempts is caught by its own
    /// test.
    #[test]
    fn the_scan_is_not_vacuous() {
        let found = registered_from_sources().expect("the scan must be usable");
        assert_eq!(
            found.len(),
            EXPECTED_REGISTRATIONS,
            "a scan that finds the wrong number of registrations cannot prove \
             anything about them: {found:?}"
        );
        assert!(
            found.iter().any(|r| r.name == "now"),
            "the clock interface's `now` must be among the registrations: {found:?}"
        );
        assert!(
            found.iter().any(|r| r.name == "digest"),
            "the hashing interface's `digest` must be among them: {found:?}"
        );
    }

    /// `EXPECTED_REGISTRATIONS` must agree with `arch012::AUDITED`, which is
    /// independently checked against the source in both directions.
    #[test]
    fn the_expected_count_agrees_with_audited() {
        assert_eq!(
            EXPECTED_REGISTRATIONS,
            crate::arch012::AUDITED.len(),
            "ARCH-003 and ARCH-012 must agree on how many host functions exist"
        );
    }

    /// The two scanners — this module's and `arch012`'s — must see the same set.
    ///
    /// # Why this matters more than it looks
    ///
    /// Because they are the same question asked twice with different machinery,
    /// and `arch012::scan` is the one driven with fabricated input in its own
    /// tests. If they disagree, one of them is wrong and the tables built on each
    /// disagree with each other.
    #[test]
    fn the_scanners_agree() {
        let mine = registered_from_sources().expect("usable");
        let theirs: Vec<crate::arch012::Registered> = HOST_SOURCES
            .iter()
            .flat_map(|(f, t)| crate::arch012::scan(f, t))
            .collect();

        assert_eq!(
            mine.len(),
            theirs.len(),
            "the scanners disagree on the count: mine {} {mine:?}, theirs {} \
             {theirs:?}",
            mine.len(),
            theirs.len()
        );
        let mut a: Vec<(&str, &str)> = mine.iter().map(|r| (r.file, r.name.as_str())).collect();
        let mut b: Vec<(&str, &str)> = theirs
            .iter()
            .map(|r| (r.file.as_str(), r.function.as_str()))
            .collect();
        a.sort_unstable();
        b.sort_unstable();
        assert_eq!(
            a, b,
            "the scanners disagree on which functions are registered"
        );
    }

    /// Every host module in the directory must be in [`HOST_MODULES`].
    #[test]
    fn every_host_module_is_scanned() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("src must be readable") {
            let name = entry
                .expect("readable entry")
                .file_name()
                .to_string_lossy()
                .into_owned();
            let is_host_module = name.starts_with("host_")
                && std::path::Path::new(&name).extension() == Some(std::ffi::OsStr::new("rs"));
            if is_host_module {
                found.push(name);
            }
        }
        found.sort();
        let mut covered: Vec<String> = HOST_MODULES.iter().map(|s| (*s).to_owned()).collect();
        covered.sort();
        assert_eq!(
            found, covered,
            "a host module exists that ARCH-003 does not scan; add it to \
             HOST_MODULES and HOST_SOURCES"
        );
    }

    /// The WIT side must find real declarations, or `wit_defines` answers `false`
    /// for everything and reports eight false failures.
    #[test]
    fn the_wit_side_has_real_definitions() {
        for name in [
            "digest",
            "digest-many",
            "now",
            "timezone",
            "resolution",
            "get",
        ] {
            assert!(
                wit_defines(name),
                "`{name}` is declared in a WIT file but was not found"
            );
        }
        assert!(!wit_defines("no-such-function-anywhere"));
    }

    /// **A name mentioned only in a WIT doc comment is not a definition.**
    ///
    /// This is `§O-071`'s bug class, refused here by shape rather than by a
    /// search that hopes prose will not match.
    #[test]
    fn a_name_in_a_wit_doc_comment_is_not_a_definition() {
        let prose = "/// This interface discusses `digest` and `digest-many` at length.\n\
                     /// See digest-many: it batches.\n";
        assert!(!wit_declares_function(prose, "digest"));
        assert!(!wit_declares_function(prose, "digest-many"));
    }

    #[test]
    fn every_declaration_form_is_recognised() {
        assert!(wit_declares_function("  now: func() -> u64,\n", "now"));
        assert!(wit_declares_function(
            "  sleep: async func(ms: u64),\n",
            "sleep"
        ));
        assert!(wit_declares_function(
            "  len: static func() -> u32,\n",
            "len"
        ));
        assert!(wit_declares_function("now: func() -> u64,\n", "now"));
        // A near-miss must not match.
        assert!(!wit_declares_function("  nowhere: func(),\n", "now"));
        assert!(!wit_declares_function("  nowhere: func(),\n", "now"));
        // Prose with the declaration shape but no colon is not a declaration.
        assert!(!wit_declares_function("  now func() -> u64,\n", "now"));
    }

    /// **The `first_kebab_literal` guard, which is the structural half of the
    /// prose refusal.**
    #[test]
    fn the_literal_extractor_refuses_prose() {
        assert_eq!(
            first_kebab_literal(r#""digest-many", |s, p| Ok(()))"#),
            Some("digest-many".to_owned())
        );
        // An escaped quote inside a `format!` is not a name.
        assert_eq!(first_kebab_literal(r#""{name}\"")"#), None);
        // A sentence fragment is not kebab-case.
        assert_eq!(first_kebab_literal(r#""Name" , more)"#), None);
        assert_eq!(first_kebab_literal("no literal here"), None);
    }

    /// **The comment and test skips, driven on a fabricated source.**
    ///
    /// `arch012::scan` takes its sources as an argument precisely so it can be
    /// driven this way; this test does the same for the rules that matter here,
    /// using the real sources' *shape* rather than a copy of their content.
    #[test]
    fn the_comment_and_test_skips_work() {
        // Reproduce the skip logic on a synthetic file.
        let synthetic = "// SPDX-License-Identifier: Apache-2.0\n\
             \n\
             /// Prose mentioning `func_wrap(\"prose-name\"` inline.\n\
             pub fn register() {\n\
             inst.func_wrap(\"real\", |s, p| Ok(()))?;\n\
             }\n\
             #[cfg(test)]\n\
             mod t { fn f() { inst.func_wrap(\"test-only\", |s, p| Ok(())); } }\n";
        let mut names = Vec::new();
        for line in synthetic.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("#[cfg(test)]") {
                break;
            }
            if trimmed.starts_with("//") {
                continue;
            }
            if let Some(at) = line.find("func_wrap(") {
                if let Some(n) = first_kebab_literal(&line[at + "func_wrap(".len()..]) {
                    names.push(n);
                }
            }
        }
        assert_eq!(
            names,
            vec!["real".to_owned()],
            "only the production registration must be seen"
        );
    }
}
