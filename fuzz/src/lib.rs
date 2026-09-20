//! The corpus harness — `SEC-012`, and what makes the fuzzing programme real in
//! **ordinary** CI.
//!
//! # The problem this solves
//!
//! `SEC-012` asks for a fuzzing programme; `SEC-013` asks for `cargo-fuzz`
//! targets on a nightly schedule. Those are two different things, and building
//! only the second produces a programme that runs **when someone remembers** —
//! once a night, in a job whose failure nobody reads until the next morning, on
//! code that has already been merged.
//!
//! The value of a fuzzer comes from two separate mechanisms, and they have
//! different cadences:
//!
//! | Mechanism | Cadence | What it finds |
//! |---|---|---|
//! | **Random exploration** | nightly, sustained | Unknown shapes; deep bugs |
//! | **Regression corpus** | every commit, seconds | A bug that was found once and comes back |
//!
//! The second is the one that must be in every build. A crash found by a nightly
//! run is worthless if the input that caused it is not retained and re-run on
//! every subsequent commit — the bug will be reintroduced by an unrelated change
//! and found again, later, by luck.
//!
//! # What this harness is, precisely
//!
//! It is a **deterministic, seeded, bounded** corpus runner that exercises the
//! same properties as the `libfuzzer` targets, using no nightly features and no
//! external tooling. It runs on stable Rust, in every `cargo test`, in
//! milliseconds. It is not a fuzzer and does not pretend to be one:
//!
//! * It explores a **fixed, seeded** set of inputs, so a failure is reproducible
//!   from the seed alone.
//! * It runs a **bounded** number of iterations, so it cannot make CI slow.
//! * It asserts the **same invariants** the fuzz targets assert, so a property
//!   that regresses fails here first — on the commit that broke it.
//!
//! # The seed corpus is a deliverable, not a convenience
//!
//! [`CORPUS`] holds inputs that were **chosen because they are interesting**, not
//! generated: valid manifests, near-valid manifests, truncations of both, and the
//! malformed shapes that a hand-written parser most often mishandles. When the
//! nightly fuzzer finds a new crash, the input is added here, and from that
//! moment it is checked on every commit. That promotion step is what turns a
//! fuzzing run into a regression suite, and it is the reason this module exists
//! rather than the programme being "the nightly job".

use qqq_cap::manifest::Manifest;

/// Documents that exercise the manifest parser's shapes.
///
/// # Why these particular inputs
///
/// Each entry is a shape rather than a random string, because a corpus of random
/// bytes tests the TOML lexer and nothing else. The categories, and the parser
/// behaviour each probes:
///
/// | Category | What it probes |
/// |---|---|
/// | Minimal and full valid | The accept path, and that a complete manifest parses |
/// | Missing required fields | That absence is an error, not a default |
/// | Structural corruption | Unclosed tables, duplicate keys, bad types |
/// | Adversarial values | Huge numbers, negative limits, unicode, NUL, traversal |
/// | Encoding edges | Invalid UTF-8 is handled by the caller; BOM and CRLF are here |
pub const CORPUS: &[&str] = &[
    // -- Minimal and complete valid documents -------------------------------
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
    // -- Missing required fields --------------------------------------------
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
    "\u{feff}[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
    "[package]\r\nname = \"a\"\r\nversion = \"0.1.0\"\r\n",
    // -- Adversarial values ---------------------------------------------------
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[limits]\nfuel = 18446744073709551615\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[limits]\nfuel = 0\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[limits]\nmax_instances = 0\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[limits]\nmax_subrequests = 4294967295\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[limits]\nmemory = \"0\"\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[limits]\nmemory = \"99999999999999GiB\"\n",
    "[package]\nname = \"../etc/passwd\"\nversion = \"0.1.0\"\n",
    "[package]\nname = \"a\\u{0}b\"\nversion = \"0.1.0\"\n",
    "[package]\nname = \"caf\u{e9} \u{65e5}\u{672c}\u{8a9e}\"\nversion = \"0.1.0\"\n",
    "[package]\nname = \"a\"\nversion = \"not.a.version\"\n",
    // -- Truncations of a valid document, which is what a network cut produces --
    "[package]\nname = \"orders\"\nversion = \"1.0.",
    "[package]\nname = \"orders\"\nversion = \"1.0.0\"\n\n[lim",
    "[package]\nname = \"orders\"\nversion = \"1.0.0\"\n\n[limits]\nmemory = \"128Mi",
    // -- Capability shapes the grant derivation must handle -------------------
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.crypto]\nrandom = true\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.crypto]\nhash = []\n",
    // `fs` is an ARRAY of tables (`[[capabilities.fs]]`), not a table with
    // `read`/`write` lists. The first version of this corpus used the table form
    // and the parser rejected it — correctly, and the rejection is what taught me
    // the shape. The rejected form stays in the corpus below so the mistake is
    // pinned rather than forgotten.
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[[capabilities.fs]]\npath = \"/data\"\nmode = \"read\"\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[[capabilities.fs]]\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[[capabilities.fs]]\npath = \"/data\"\nmode = \"nonsense\"\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.env]\nallow = [\"\"]\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.clock]\nwall = true\n",
    "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.unknown]\nx = 1\n",
];

/// Inputs the parser must **reject**, with the shape that makes each interesting.
///
/// # Why this is separate from [`CORPUS`]
///
/// [`CORPUS`] feeds a harness that asserts determinism and totality on whatever
/// the parser does — it does not care which way each input goes. This table
/// asserts the *decision*, so it holds only inputs whose rejection is a real
/// requirement: a wrong shape, an unknown key, a value out of range. Keeping the
/// two apart means adding an input to `CORPUS` cannot accidentally weaken an
/// assertion about what must be refused.
pub const MUST_REJECT_CORPUS: &[(&str, &str)] = &[
    (
        "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.fs]\nread = [\"/data\"]\n",
        "`fs` is an array of tables, not a table with read/write lists",
    ),
    (
        "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[limits]\nfuel = 0\n",
        "a zero fuel budget permits no work at all",
    ),
    (
        "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[limits]\nmax_instances = 0\n",
        "zero instances makes the runtime unusable",
    ),
    (
        "[package]\nname = \"../etc/passwd\"\nversion = \"0.1.0\"\n",
        "a package name that is a path traversal",
    ),
    (
        "[package]\nname = \"a\"\nversion = \"not.a.version\"\n",
        "a version that is not semver",
    ),
    (
        "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.unknown]\nx = 1\n",
        "an unknown capability table must not be silently ignored",
    ),
];

/// Run the corpus against the manifest parser, asserting every invariant.
///
/// # Returns
///
/// `(parsed, rejected)` — the counts, so a caller can assert the corpus is
/// balanced. A corpus that all parses, or all fails, tests one path.
///
/// # Panics
///
/// Panics on any invariant violation, naming the input. A test helper that
/// returned `Result` would let a caller ignore it, and the whole point is that
/// these properties are not optional.
#[must_use]
pub fn run_manifest_corpus() -> (usize, usize) {
    let mut parsed = 0;
    let mut rejected = 0;

    for input in CORPUS {
        let first = std::panic::catch_unwind(|| Manifest::parse(input)).unwrap_or_else(|_| {
            panic!(
                "the manifest parser panicked on a corpus input ({input:?}); with \
                 `panic = \"abort\"` in release, a panic here aborts the build server"
            )
        });

        match first {
            Err(_) => rejected += 1,
            Ok(manifest) => {
                parsed += 1;

                // **Determinism.** The same bytes must always produce the same
                // manifest. A parser whose output varied would make every build
                // irreproducible (§D-007) in a way no single-run test can see.
                let again = Manifest::parse(input)
                    .unwrap_or_else(|_| panic!("the parser accepted then refused {input:?}"));
                assert_eq!(
                    manifest, again,
                    "the manifest parser is nondeterministic on {input:?}"
                );

                // **Grant derivation is a pure function of the manifest.** Two
                // derivations must agree; a set with an unordered internal
                // collection would surface here.
                let g1 = qqq_cap::resolve::GrantSet::from_manifest(&manifest);
                let g2 = qqq_cap::resolve::GrantSet::from_manifest(&manifest);
                assert_eq!(
                    g1.capabilities(),
                    g2.capabilities(),
                    "grant derivation is nondeterministic for {input:?}"
                );

                // **Debug rendering is total.** Every diagnostic in the CLI is
                // built from these values, so a panic here is a panic on the
                // surface a developer uses to understand their own manifest.
                let a = format!("{manifest:?}");
                let b = format!("{manifest:?}");
                assert_eq!(a, b, "rendering {input:?} is unstable across runs");
            }
        }
    }

    (parsed, rejected)
}

/// The traversal strings that must **always** be refused as paths.
///
/// Shared between this harness and the `host_interfaces` fuzz target so the two
/// cannot diverge: a corpus duplicated in two places is a corpus that drifts, and
/// the copy nobody updates is the one that stops testing anything.
pub const TRAVERSAL_CORPUS: &[&str] = &[
    "/var/lib/orders/../../../etc/passwd",
    "../etc/passwd",
    "/data/../../etc",
    "..",
    "a/..",
    "a/../..",
    "/data/x/../y",
    "foo\\..\\bar",
    "\\..\\",
    "/data/..",
    "/data/../",
];

/// The path shapes that are **legitimate** and must be admitted.
///
/// # Why the negative control is in the same table
///
/// A shape check that refused everything would satisfy every entry in
/// [`TRAVERSAL_CORPUS`] while making every filesystem grant useless — which is
/// the §O-067 lesson, where a defence that passed the attack it existed to stop
/// was worse than none because it *looked* like protection. The control is what
/// makes the attack assertions mean something.
pub const LEGITIMATE_PATH_CORPUS: &[&str] = &[
    "/var/lib/orders/data.csv",
    "orders/data.csv",
    "data.csv",
    "./data.csv",
    "/a/b/c",
    // Components that merely CONTAIN dots: a substring search would refuse
    // every one of these, which is what separates a component check from a
    // `contains("..")` check.
    "/data/..hidden",
    "/data/a..b",
    "/data/...",
    "/data/file.tar..gz",
];

/// Run the path corpus, asserting both directions.
///
/// # Panics
///
/// On any attack that is accepted, or any legitimate path that is refused.
#[must_use]
pub fn run_path_corpus() -> usize {
    let mut checked = 0;

    for attack in TRAVERSAL_CORPUS {
        assert!(
            qqq_host::boundary::path_shape("path", attack).is_reject(),
            "the traversal corpus entry `{attack}` was ACCEPTED; a defence that passes \
             the attack it exists to stop is worse than none, because it looks like \
             protection and nobody adds the real one (§O-067)"
        );
        checked += 1;
    }

    for legitimate in LEGITIMATE_PATH_CORPUS {
        assert!(
            qqq_host::boundary::path_shape("path", legitimate).is_accept(),
            "the legitimate path `{legitimate}` was REFUSED; a check that refuses \
             everything satisfies every attack assertion above while making every \
             filesystem grant useless"
        );
        checked += 1;
    }

    // And the rendering every diagnostic goes through must be injection-safe on
    // every corpus entry, because each one is attacker-controlled text.
    for input in TRAVERSAL_CORPUS.iter().chain(LEGITIMATE_PATH_CORPUS) {
        let rendered = qqq_host::boundary::render_for_diagnostic(input);
        assert!(
            !rendered.contains('\n') && !rendered.contains('\r'),
            "rendering `{input}` produced a raw newline, which forges a log line"
        );
        assert!(
            rendered.len() <= qqq_host::boundary::MAX_ECHO_BYTES + 32,
            "rendering `{input}` produced {} bytes, exceeding the bound",
            rendered.len()
        );
    }

    checked
}

/// A deterministic byte generator, for the bounded exploration below.
///
/// # Why not `rand`
///
/// Because a fuzzing harness whose corpus depends on an RNG version is a harness
/// whose failures stop reproducing when that crate updates. This is `splitmix64`:
/// fifteen lines, no dependency, and identical across platforms and versions —
/// which is what makes a failure from seed `N` reproducible from `N` alone.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// A generator from a seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The next value.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A byte vector of at most `max` bytes.
    pub fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = (self.next_u64() as usize) % (max + 1);
        (0..len).map(|_| (self.next_u64() & 0xFF) as u8).collect()
    }
}

/// Run a bounded, seeded exploration of the boundary checks.
///
/// # Why this exists when the `libfuzzer` targets already do it
///
/// Because those need nightly and a fuzzing toolchain, and this needs neither. It
/// runs in every `cargo test`, so a property that regresses fails on the commit
/// that broke it rather than in a nightly job whose result nobody reads until
/// morning. The two are complements: this is the fast net, `libfuzzer` is the
/// wide one.
///
/// # Returns
///
/// The number of inputs explored, so a test can assert the exploration actually
/// happened — an exploration loop that ran zero times would pass every assertion
/// inside it.
#[must_use]
pub fn explore_boundary_checks(seed: u64, iterations: usize) -> usize {
    use qqq_host::boundary::{self, Verdict};

    let mut rng = SplitMix64::new(seed);
    let mut explored = 0;

    for _ in 0..iterations {
        let data = rng.bytes(256);
        explored += 1;

        // Every check must be total. The `Verdict` is inspected so the compiler
        // cannot optimise the call away, and a rejection's reason must be safe to
        // log — which is the property that matters because the reasons embed
        // attacker-controlled text.
        let verdicts = [
            boundary::path_shape("path", &String::from_utf8_lossy(&data)),
            boundary::text("text", &String::from_utf8_lossy(&data), 256),
            boundary::path_component("component", &String::from_utf8_lossy(&data)),
            boundary::size("size", data.len(), 128),
            boundary::list_size("list", data.len(), data.len()),
            boundary::discriminant("disc", data.len() as u32, 3),
            boundary::range_within("range", data.len() as u64, 1, 128),
            boundary::consistent_length("len", data.len() as u64, 1),
        ];

        for v in &verdicts {
            if let Verdict::Reject { reason } = v {
                assert!(
                    !reason.chars().any(|c| c == '\n' || c == '\r'),
                    "a rejection contained a raw newline for input {data:?}"
                );
                assert!(
                    reason.len() < 4096,
                    "a rejection was {} bytes, unbounded by the input",
                    reason.len()
                );
            }
        }
    }

    explored
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The corpus actually exercises both paths.
    #[test]
    fn the_manifest_corpus_parses_some_inputs_and_rejects_others() {
        let (parsed, rejected) = run_manifest_corpus();
        assert_eq!(parsed + rejected, CORPUS.len());
        // The thresholds are deliberately loose. A tight lower bound would turn
        // every future corpus addition into a test failure that its author
        // "fixes" by editing the number, which is how a balance check stops
        // meaning anything. What matters is that neither path is empty and that
        // both are substantially exercised.
        assert!(
            parsed >= 6,
            "only {parsed} corpus inputs parse; a corpus that is almost all \
             rejections tests the error path and nothing else"
        );
        assert!(
            rejected >= 10,
            "only {rejected} corpus inputs are rejected; a corpus that almost \
             everything parses tests the accept path and nothing else"
        );
    }

    /// **Every input in `MUST_REJECT_CORPUS` is refused, for a stated reason.**
    ///
    /// # Why each entry carries its justification
    ///
    /// Because "this manifest must not parse" is a *security* claim for several of
    /// these — an unknown capability table that parsed would be a manifest whose
    /// declared authority and effective authority differ, and a package name that
    /// is a path traversal would reach the filesystem. A table of inputs with no
    /// reasons is a table whose entries nobody can review, and an entry that is no
    /// longer a requirement is one that should be deleted rather than kept.
    #[test]
    fn the_must_reject_corpus_is_refused() {
        for (input, why) in MUST_REJECT_CORPUS {
            assert!(
                Manifest::parse(input).is_err(),
                "this manifest PARSED but must not ({why}): {input:?}"
            );
        }
        assert!(
            MUST_REJECT_CORPUS.len() >= 5,
            "the must-reject corpus is too small to be a corpus"
        );
    }

    #[test]
    fn the_path_corpus_holds_in_both_directions() {
        let n = run_path_corpus();
        assert_eq!(n, TRAVERSAL_CORPUS.len() + LEGITIMATE_PATH_CORPUS.len());
        assert!(TRAVERSAL_CORPUS.len() >= 10, "the attack corpus is too small");
        assert!(
            LEGITIMATE_PATH_CORPUS.len() >= 5,
            "the control corpus is too small to make the attack assertions mean anything"
        );
    }

    /// The exploration runs the iteration count it claims.
    #[test]
    fn the_exploration_is_bounded_and_actually_runs() {
        assert_eq!(explore_boundary_checks(1, 0), 0);
        assert_eq!(explore_boundary_checks(1, 100), 100);
        assert_eq!(explore_boundary_checks(0xDEAD_BEEF, 1_000), 1_000);
    }

    /// The generator is deterministic and platform-independent.
    ///
    /// Pinned to exact values, because the reproducibility of a failure from its
    /// seed is the property that makes this harness useful. A generator that
    /// changed would silently invalidate every recorded seed.
    #[test]
    fn the_generator_is_deterministic_and_pinned() {
        let mut a = SplitMix64::new(0);
        let first: Vec<u64> = (0..4).map(|_| a.next_u64()).collect();
        let mut b = SplitMix64::new(0);
        let second: Vec<u64> = (0..4).map(|_| b.next_u64()).collect();
        assert_eq!(first, second, "the generator is not deterministic");

        // The exact sequence, so a change to the algorithm is a test failure
        // rather than a silent invalidation of every recorded seed.
        assert_eq!(
            first,
            vec![
                16294208416658607535,
                7960286522194355700,
                487617019471545679,
                17909611376780542444,
            ],
            "the generator's sequence changed; every recorded failing seed is now \
             meaningless and must be re-derived"
        );

        // A different seed gives a different stream.
        let mut c = SplitMix64::new(1);
        assert_ne!(c.next_u64(), first[0]);
    }

    /// `bytes` respects its ceiling, including at the boundary.
    #[test]
    fn the_generator_respects_its_length_ceiling() {
        let mut g = SplitMix64::new(42);
        for _ in 0..500 {
            let b = g.bytes(64);
            assert!(b.len() <= 64, "generated {} bytes for a ceiling of 64", b.len());
        }
        // A ceiling of zero yields empty, never a long vector.
        let mut g = SplitMix64::new(7);
        for _ in 0..10 {
            assert!(g.bytes(0).is_empty());
        }
    }

    /// The two corpus tables are what the fuzz target uses, so they cannot drift.
    ///
    /// This is the promotion mechanism stated as a test: a corpus entry that
    /// exists in only one place is an entry that stops being checked when the
    /// other place changes.
    #[test]
    fn the_corpora_are_non_empty_and_distinct() {
        assert!(!CORPUS.is_empty());
        assert!(!TRAVERSAL_CORPUS.is_empty());
        assert!(!LEGITIMATE_PATH_CORPUS.is_empty());
        // No entry appears in both path tables — an input that is both an attack
        // and legitimate would make the pair of assertions contradictory.
        for attack in TRAVERSAL_CORPUS {
            assert!(
                !LEGITIMATE_PATH_CORPUS.contains(attack),
                "`{attack}` appears in both the attack and the control corpus, so the \
                 two assertions contradict each other"
            );
        }
    }
}
