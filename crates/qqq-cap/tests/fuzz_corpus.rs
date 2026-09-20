//! The regression corpus — `SEC-012`'s always-on half.
//!
//! # Why this file exists rather than the corpus living only in `fuzz/`
//!
//! `SEC-012` asks for a fuzzing programme and `SEC-013` for `cargo-fuzz` targets
//! on a nightly schedule. Those are two mechanisms with different cadences, and
//! building only the second produces a programme that runs **when someone
//! remembers** — once a night, in a job whose failure nobody reads until morning,
//! on code that is already merged.
//!
//! | Mechanism | Cadence | What it finds |
//! |---|---|---|
//! | Random exploration (`fuzz/`) | nightly, sustained | Unknown shapes; deep bugs |
//! | **Regression corpus** (this file) | every commit, milliseconds | A bug found once, coming back |
//!
//! The second is what must be in every build, because a crash found by a nightly
//! run is worthless if the input that caused it is not re-run on every subsequent
//! commit. The bug would be reintroduced by an unrelated change and found again,
//! later, by luck.
//!
//! # Where the corpus lives, and why not here
//!
//! The tables are defined **once**, in `qqq-host`'s `boundary` module and in this
//! file's own [`MANIFESTS`], and the `fuzz/` workspace reads its copies from the
//! same shape. A corpus duplicated across two crates drifts, and the copy nobody
//! updates is the one that stops testing anything — so the duplication is kept
//! deliberately small and each table states what it is for.
//!
//! # What a corpus entry is
//!
//! Every entry is an input that was **chosen because it is interesting**, not
//! generated: valid documents, near-valid ones, truncations, and the malformed
//! shapes a hand-written parser most often mishandles. When the nightly fuzzer
//! finds a new crash, the input is added here, and from that moment it is checked
//! on every commit. **That promotion step is what turns a fuzzing run into a
//! regression suite**, and it is the reason this file exists.

use qqq_cap::manifest::Manifest;
use qqq_cap::resolve::GrantSet;

/// Documents that exercise the manifest parser's shapes.
///
/// # Why these particular inputs
///
/// Each is a *shape*, because a corpus of random bytes tests the TOML lexer and
/// nothing else — the lexer is a dependency's problem, not QQQ's. The categories:
///
/// | Category | What it probes |
/// |---|---|
/// | Valid, minimal and complete | The accept path, and that a full manifest parses |
/// | Missing required fields | That absence is an error, not a default |
/// | Structural corruption | Unclosed tables, duplicate keys, bad types |
/// | Adversarial values | Huge numbers, zero limits, traversal, unicode, BOM |
/// | Truncations | What a cut connection or a partial write produces |
/// | Capability shapes | That the grant derivation handles every declared form |
pub const MANIFESTS: &[&str] = &[
    // -- Valid ---------------------------------------------------------------
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
    "[package]\nname = \"qqq-app\"\nversion = \"1.2.3\"\n",
    concat!(
        "[package]\nname = \"orders\"\nversion = \"1.0.0\"\n\n",
        "[limits]\nmemory = \"128MiB\"\nfuel = 50000000\nepoch_deadline_ms = 5000\n",
        "max_instances = 200\nmax_open_handles = 256\nmax_subrequests = 32\n"
    ),
    concat!(
        "[package]\nname = \"full\"\nversion = \"1.0.0\"\n\n",
        "[[capabilities.fs]]\npath = \"/data\"\nmode = \"read\"\n\n",
        "[capabilities.crypto]\nrandom = true\nhash = [\"sha256\", \"blake3\"]\n\n",
        "[capabilities.env]\nallow = [\"LOG_LEVEL\"]\n\n",
        "[server]\ndefault_auth = \"bearer-jwt\"\n"
    ),
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.crypto]\nrandom = true\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.crypto]\nhash = []\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[[capabilities.fs]]\npath = \"/data\"\nmode = \"read\"\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.env]\nallow = [\"\"]\n",
    // A BOM and CRLF: what a Windows-authored file looks like on the wire.
    "\u{feff}[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
    "[package]\r\nname = \"a\"\r\nversion = \"0.1.0\"\r\n",
    // -- Missing required fields ---------------------------------------------
    "",
    "[package]\n",
    "[package]\nname = \"a\"\n",
    "[package]\nversion = \"0.1.0\"\n",
    "[limits]\n",
    // -- Structural corruption -----------------------------------------------
    "[package\nname = \"a\"\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[[[\n",
    "[package]\nname = \"a\"\nname = \"b\"\nversion = \"0.1.0\"\n",
    "[package]\nname = 123\nversion = \"0.1.0\"\n",
    "[package]\nname = \"a\"\nversion = 1.0\n",
    "[limits]\nfuel = \"not a number\"\n",
    "[limits]\nmemory = 12345\n",
    "not toml at all\n",
    "= = =\n",
    // -- Adversarial values ---------------------------------------------------
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[limits]\nfuel = 18446744073709551615\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[limits]\nfuel = 0\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[limits]\nmax_instances = 0\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[limits]\nmax_subrequests = 4294967295\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[limits]\nmemory = \"0\"\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[limits]\nmemory = \"99999999999999GiB\"\n",
    "[package]\nname = \"../etc/passwd\"\nversion = \"0.1.0\"\n",
    "[package]\nname = \"caf\u{e9} \u{65e5}\u{672c}\u{8a9e}\"\nversion = \"0.1.0\"\n",
    "[package]\nname = \"a\"\nversion = \"not.a.version\"\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.unknown]\nx = 1\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[[capabilities.fs]]\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[[capabilities.fs]]\npath = \"/data\"\nmode = \"nonsense\"\n",
    // -- Truncations: what a cut connection or a partial write produces --------
    "[package]\nname = \"orders\"\nversion = \"1.0.",
    "[package]\nname = \"orders\"\nversion = \"1.0.0\"\n\n[lim",
    "[package]\nname = \"orders\"\nversion = \"1.0.0\"\n\n[limits]\nmemory = \"128Mi",
];

/// **The corpus harness.** Every invariant the parser must hold, on every input.
///
/// # The invariants, and the failure each prevents
///
/// 1. **No panic, ever.** With `panic = "abort"` in the release profile, a panic
///    here aborts the build server or the host — a denial of service reachable
///    from a file.
/// 2. **Determinism.** The same bytes must yield the same manifest. Nondeterminism
///    would make every build irreproducible (§D-007) in a way no single-run test
///    can see.
/// 3. **Grant derivation is a pure function of the manifest.** Two derivations
///    must agree. If the manifest held an unordered collection, the *effective*
///    authority could vary between the host's derivation and `qqqai why`'s — which
///    is the one disagreement the capability model must never have.
/// 4. **Renderings are stable and total.** Every diagnostic in the CLI is built
///    from these values, so a panic here is a panic on the developer's own
///    tooling.
#[test]
fn the_manifest_corpus_holds_every_invariant() {
    let mut parsed = 0_usize;
    let mut rejected = 0_usize;

    for input in MANIFESTS {
        // 1. No panic.
        let outcome = std::panic::catch_unwind(|| Manifest::parse(input));
        let result = outcome.unwrap_or_else(|_| {
            panic!(
                "the manifest parser PANICKED on a corpus input ({input:?}); with \
                 `panic = \"abort\"` in release, a panic here aborts the process"
            )
        });

        let manifest = match result {
            Err(_) => {
                rejected += 1;
                continue;
            }
            Ok(m) => {
                parsed += 1;
                m
            }
        };

        // 2. Determinism.
        let again = Manifest::parse(input)
            .unwrap_or_else(|_| panic!("the parser accepted then refused {input:?}"));
        assert_eq!(
            manifest, again,
            "the manifest parser is NONDETERMINISTIC on {input:?}; two parses of the \
             same bytes produced different manifests, which makes every build \
             irreproducible"
        );

        // 3. Grant derivation is pure.
        let g1 = GrantSet::from_manifest(&manifest);
        let g2 = GrantSet::from_manifest(&manifest);
        assert_eq!(
            g1.capabilities(),
            g2.capabilities(),
            "grant derivation is nondeterministic for {input:?}; the host's effective \
             authority and `qqqai why`'s report could disagree, which is the one \
             disagreement the capability model must never have"
        );

        // 4. Renderings are stable.
        let a = format!("{manifest:?}");
        let b = format!("{manifest:?}");
        assert_eq!(a, b, "rendering {input:?} is unstable across runs");
    }

    // The balance is asserted so the corpus cannot silently degenerate into
    // testing one path. The bounds are loose on purpose: a tight bound turns
    // every future addition into a failure its author "fixes" by editing the
    // number, which is how a balance check stops meaning anything.
    assert_eq!(parsed + rejected, MANIFESTS.len());
    assert!(
        parsed >= 6,
        "only {parsed} of {} corpus inputs parse; the accept path is barely tested",
        MANIFESTS.len()
    );
    assert!(
        rejected >= 10,
        "only {rejected} of {} corpus inputs are rejected; the error path is barely \
         tested",
        MANIFESTS.len()
    );
}

/// **Every syntax error reports a line that is inside the file — `§O-072`.**
///
/// # The defect this pins
///
/// `toml`'s `Span::start` is documented as a **byte index**, and it was assigned
/// directly to a field rendered as `qqq.toml line {n}`. So a three-line manifest
/// with an unclosed header reported *"line 8"*, and a forty-line file reported
/// line numbers in the thousands. The error grew with the file's byte length
/// rather than its line count.
///
/// This is the assertion that catches the whole class without needing to know the
/// right answer for each input: a byte offset exceeds the line count as soon as a
/// file has more bytes than lines, which is every real manifest.
#[test]
fn every_syntax_error_reports_a_line_inside_the_file() {
    let mut checked = 0_usize;

    for input in MANIFESTS {
        let line_count = input.lines().count().max(1);
        let Err(err) = Manifest::parse(input) else {
            continue;
        };
        let qqq_cap::manifest::ManifestError::Syntax { line, detail } = err else {
            continue;
        };
        let Some(line) = line else { continue };

        assert!(
            (1..=line_count).contains(&line),
            "a malformed manifest with {line_count} line(s) reported a SYNTAX error at \
             line {line}, outside the file. A byte offset masquerading as a line number \
             is exactly the §O-072 defect.\nInput: {input:?}\nDetail: {detail}"
        );
        checked += 1;
    }

    assert!(
        checked >= 5,
        "only {checked} inputs produced a located syntax error, so this check is \
         barely exercised; a test that mostly skips its own body proves nothing"
    );
}
