// SPDX-License-Identifier: Apache-2.0

//! Module preloading: compile at deploy, not on the first request -- `HOST-021`.
//!
//! # What the problem actually is
//!
//! §2.3 sets two budgets for the same operation:
//!
//! > Cold start budget: Component instantiation <= 100 us warm-pool, **<= 5 ms
//! > cold-from-cache**.
//!
//! The 5 ms figure is *cold from cache* -- an AOT `.cwasm` compiled ahead of time
//! and loaded. Compiling from source is a different order of magnitude entirely:
//! Cranelift on a real component is tens to hundreds of milliseconds. So the first
//! request to a freshly deployed host pays a cost that no subsequent request pays,
//! and that cost appears as a latency spike on exactly the request an operator is
//! watching after a deploy.
//!
//! Preloading moves that work to deploy time, where it is paid once, in a phase
//! that is already allowed to be slow.
//!
//! # Why the AOT cache is required rather than optional
//!
//! Preloading without a cache would compile eagerly and then **throw the result
//! away** unless it is persisted, since a `Component` lives in one engine. The
//! cache is what makes the eager work durable, and
//! [`crate::config::aot_cache_key`] is what makes it safe -- it keys on the
//! component digest, the target triple and the engine version, so a stale artifact
//! cannot be loaded into an engine that did not produce it.
//!
//! # What this module does and does not do
//!
//! It **does**: decide what to preload, do it against one engine, and report per
//! item outcomes including timing.
//!
//! It **does not**: perform file I/O. The `.cwasm` bytes are handed back to the
//! caller, which writes them. That keeps this module free of the filesystem (so it
//! is testable without one) and keeps §4.3's layering intact -- `qqq-host` owns the
//! engine, not the disk.
//!
//! # Failure policy: partial success is the only useful outcome
//!
//! If one component in a set fails to compile, the sensible response is to preload
//! the rest and report the failure -- not to abandon the whole deploy. A preloader
//! that returned `Err` on the first bad artifact would leave an operator with
//! *nothing* preloaded and one error, which is strictly worse than ninety-nine
//! preloaded and one error.
//!
//! So [`preload`] always returns a [`PreloadReport`], and the report carries
//! [`PreloadReport::failed`] for the caller to act on. The decision about what to
//! do with a failure belongs to the deploy tool, which knows whether the failed
//! component matters.

use std::time::{Duration, Instant};

use qqq_core::{Error, ErrorCode, Result};

use crate::admission::HostCapacity;
use crate::config::{EngineConfig, aot_cache_key, build_engine, target_triple};

/// One component to preload.
///
/// `Debug` is manual rather than derived: the bytes are the bulk of the struct and
/// printing them would flood a log line. The digest is what a reader wants.
#[derive(Clone)]
pub struct PreloadItem {
    /// A human-readable name, for the report. Usually the package name.
    pub name: String,
    /// The component's bytes.
    pub bytes: Vec<u8>,
    /// The content digest of `bytes`, used as the cache key.
    ///
    /// Taken as a field rather than computed here so a caller who has already
    /// digested the artifact -- `qqq-pkg` does, for content addressing -- does not
    /// pay for it twice. The digest must be the lowercase hex-encoded SHA-256
    /// **of `bytes`** (exactly 64 `[0-9a-f]` characters); [`preload`]
    /// checks the shape before hashing and fails the item on a mismatch, so
    /// a swapped pair can never produce a cache entry under the wrong key.
    /// [`cache_key_for`] must only be called with items `preload` accepted:
    /// it keys on the digest without re-verifying, so keying a store from an
    /// unverified item would reintroduce the poisoning `preload` refuses.
    pub digest: String,
}

impl std::fmt::Debug for PreloadItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreloadItem")
            .field("name", &self.name)
            .field("digest", &self.digest)
            .field("bytes", &format_args!("{} B", self.bytes.len()))
            .finish()
    }
}

/// The outcome for one component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreloadOutcome {
    /// Compiled successfully; the bytes are the AOT artifact to cache.
    Compiled {
        /// The `.cwasm` bytes to persist under the cache key.
        cwasm: Vec<u8>,
        /// How long compilation took.
        took: Duration,
    },
    /// Compilation was attempted and failed.
    Failed {
        /// The error QQQ produced.
        error: Box<Error>,
    },
}

impl PreloadOutcome {
    /// Whether this component is ready to serve.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Compiled { .. })
    }

    /// A stable, bounded name for the outcome.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Compiled { .. } => "compiled",
            Self::Failed { .. } => "failed",
        }
    }
}

/// The result of preloading a whole set.
#[derive(Debug, Clone)]
pub struct PreloadReport {
    /// One entry per item, in the order given.
    pub outcomes: Vec<(String, PreloadOutcome)>,
    /// Wall-clock time for the whole preload.
    pub total: Duration,
}

impl PreloadReport {
    /// Items that compiled.
    pub fn ready(&self) -> impl Iterator<Item = (&str, &PreloadOutcome)> {
        self.outcomes
            .iter()
            .filter(|(_, o)| o.is_ready())
            .map(|(n, o)| (n.as_str(), o))
    }

    /// Items that failed, with the reason.
    pub fn failed(&self) -> impl Iterator<Item = (&str, &PreloadOutcome)> {
        self.outcomes
            .iter()
            .filter(|(_, o)| !o.is_ready())
            .map(|(n, o)| (n.as_str(), o))
    }

    /// How many items failed.
    ///
    /// Derived rather than stored, so it cannot disagree with the iterator --
    /// a stored count is a second source of truth for the same fact, and the two
    /// drifting is how `is_complete` starts lying.
    #[must_use]
    pub fn failures(&self) -> usize {
        self.outcomes.iter().filter(|(_, o)| !o.is_ready()).count()
    }

    /// Whether every item is ready.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.failures() == 0
    }

    /// The slowest successful compilation, if any.
    ///
    /// The number a deploy tool wants to report: it is the floor on how much
    /// slower a deploy gets as components are added.
    #[must_use]
    pub fn slowest(&self) -> Option<(&str, Duration)> {
        self.outcomes
            .iter()
            .filter_map(|(n, o)| match o {
                PreloadOutcome::Compiled { took, .. } => Some((n.as_str(), *took)),
                PreloadOutcome::Failed { .. } => None,
            })
            .max_by_key(|(_, d)| *d)
    }
}

/// Compile every item against one engine, so no first request pays for it.
///
/// # Why one engine, not one per item
///
/// An `Engine` is expensive to construct (it holds the Cranelift compiler and the
/// pooling allocator's reservation) and cheap to reuse. Constructing one per
/// component would multiply the reservation by the component count, which is the
/// over-commit failure `HOST-023` exists to prevent -- and it would make preloading
/// *cost* memory rather than save latency.
///
/// # Errors
///
/// Returns `Err` only when the set cannot be admitted on this host at all, because
/// that is a whole-set failure with nothing to report per item. A component that
/// fails on its own is reported in the [`PreloadReport`], not returned as an error
/// -- see the module docs on partial success.
pub fn preload(
    items: &[PreloadItem],
    limits: &qqq_cap::manifest::Limits,
    engine_config: &EngineConfig,
    capacity: &HostCapacity,
) -> Result<PreloadReport> {
    let started = Instant::now();

    if items.is_empty() {
        return Ok(PreloadReport {
            outcomes: Vec::new(),
            total: started.elapsed(),
        });
    }

    // One engine for the whole set. Admission runs here, so a set that cannot fit
    // is refused before any compilation work happens.
    let (engine, _admitted) = build_engine(limits, engine_config, capacity).map_err(|e| {
        Error::new(e.code, "the preload set cannot be admitted on this host")
            .with_cause(format!("{e}"))
            .with_context("items", items.len().to_string())
    })?;

    let mut outcomes = Vec::with_capacity(items.len());

    for item in items {
        let began = Instant::now();

        // Integrity before anything else: the cache is keyed on
        // `item.digest`, so bytes that do not hash to it must fail HERE
        // rather than be compiled and stored under a key that names a
        // different artifact. A mismatch is a caller bug -- two artifacts
        // swapped in the deploy pipeline -- and failing the item is what
        // keeps it from becoming a poisoned cache entry at serve time.
        if let Err(error) = check_item_digest(item) {
            outcomes.push((
                item.name.clone(),
                PreloadOutcome::Failed {
                    error: Box::new(error),
                },
            ));
            continue;
        }

        // Load-time shape validation (`F-10`): an artifact declaring more
        // memories, tables, or core modules than the pool allows per instance
        // is refused HERE, at deploy, with a limit code — not as an
        // instantiation error under load. Under pooling the allocator would
        // refuse it at precompile below anyway; under OnDemand this is the
        // only load-time check. The caps are the shared per-instance maxima,
        // so this and the pool cannot disagree.
        if let Err(reason) = crate::component_shape::validate_shape(
            &item.bytes,
            &crate::component_shape::ShapeCaps::maximum(),
        ) {
            outcomes.push((
                item.name.clone(),
                PreloadOutcome::Failed {
                    error: Box::new(
                        Error::new(
                            ErrorCode::LimitOutOfRange,
                            format!("`{}` exceeds the per-instance shape limits", item.name),
                        )
                        .with_cause(reason)
                        .with_context("digest", item.digest.clone())
                        .with_remediation(
                            "rebuild the component with fewer memories, tables, \
                             or core modules; the per-component maxima are fixed",
                        ),
                    ),
                },
            ));
            continue;
        }

        // Compilation. `precompile_component` validates as well as compiles, so a
        // malformed artifact is caught HERE rather than at first use -- which is
        // the entire point of preloading.
        let outcome = match engine.precompile_component(&item.bytes) {
            Ok(cwasm) => PreloadOutcome::Compiled {
                cwasm,
                took: began.elapsed(),
            },
            Err(e) => PreloadOutcome::Failed {
                error: Box::new(
                    Error::new(
                        ErrorCode::InvalidComponentArtifact,
                        format!("`{}` could not be preloaded", item.name),
                    )
                    .with_cause(format!("{e:#}"))
                    .with_context("digest", item.digest.clone())
                    .with_remediation(
                        "confirm the artifact is a WebAssembly COMPONENT and not a \
                         core module, and that the toolchain targets the component \
                         model (`wasm32-wasip2` or later)",
                    ),
                ),
            },
        };

        outcomes.push((item.name.clone(), outcome));
    }

    Ok(PreloadReport {
        outcomes,
        total: started.elapsed(),
    })
}

/// The content digest an item's bytes must hash to: hex-encoded SHA-256.
///
/// The same convention `qqq-run` uses for the audit record's component
/// digest, so a digest computed anywhere in the pipeline means the same
/// thing. Kept as a function rather than inline so the verification in
/// [`preload`] and the test fixtures cannot drift into two algorithms.
fn content_digest(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let sum = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in sum {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Whether a claimed digest even has the digest shape: exactly 64 lowercase
/// hex characters.
///
/// Checked before hashing so a malformed claim fails fast instead of pricing
/// a full SHA-256 over the bytes first. Uppercase is not canonical: the
/// pipeline compares digests as strings, and two spellings of one digest
/// would compare unequal.
fn digest_shape_valid(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A digest safe to echo into an error: the real thing passes through, and
/// anything longer is cut to a prefix plus its length, so a megabyte of
/// caller-supplied text cannot become a megabyte of log line.
fn capped_digest(digest: &str) -> std::borrow::Cow<'_, str> {
    if digest.len() <= 64 {
        return std::borrow::Cow::Borrowed(digest);
    }
    let prefix: String = digest.chars().take(32).collect();
    std::borrow::Cow::Owned(format!("{prefix}…[{} chars]", digest.len()))
}

/// Verify an item's claimed digest: shape first, then the hash.
///
/// Shape before substance: a malformed claim fails without pricing a hash
/// over the bytes, and the echo is capped so a huge claim does not become
/// a huge error. Returns the `Failed` error, so the loop stays flat.
fn check_item_digest(item: &PreloadItem) -> std::result::Result<(), Error> {
    if !digest_shape_valid(&item.digest) {
        return Err(Error::new(
            ErrorCode::ComponentDigestMismatch,
            format!(
                "`{}` digest `{}` is not a digest",
                item.name,
                capped_digest(&item.digest)
            ),
        )
        .with_context("digest", capped_digest(&item.digest).into_owned())
        .with_remediation(
            "pass the lowercase hex-encoded SHA-256 of the artifact bytes; \
             recompute it from the bytes rather than relabelling them",
        ));
    }
    let actual = content_digest(&item.bytes);
    if actual != item.digest {
        return Err(Error::new(
            ErrorCode::ComponentDigestMismatch,
            format!(
                "`{}` digest `{}` does not match its bytes",
                item.name, item.digest
            ),
        )
        .with_cause(format!("sha256 of the bytes is `{actual}`"))
        .with_context("digest", item.digest.clone())
        .with_remediation(
            "recompute the digest from the artifact bytes; do not \
             relabel the bytes to fit the digest",
        ));
    }
    Ok(())
}

/// The cache key an item's AOT artifact should be stored under.
///
/// Exposed rather than left to the caller because the key must agree between the
/// process that *writes* the cache and the process that *reads* it, and those are
/// different deploys. A key computed differently in the two places is a cache that
/// silently never hits -- the failure mode that makes an AOT cache look useless
/// rather than broken.
#[must_use]
pub fn cache_key_for(item: &PreloadItem, engine_config: &EngineConfig) -> String {
    // `target_triple()` already returns `&'static str` and `aot_cache_key` takes
    // `&str`, so neither a borrow nor a binding is needed. Two earlier versions
    // of this line each added one, from assumptions about the return type rather
    // than from reading its signature.
    aot_cache_key(&item.digest, target_triple(), engine_config)
}

// Test indexing (`F-18`): assertions index vectors built inline above.
// One module-level reason, not per-site noise; shipping code above
// carries no such allowance.
#[allow(
    clippy::indexing_slicing,
    reason = "test assertions index inline vectors"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use qqq_cap::manifest::Limits;

    /// A minimal valid component: magic, version, and an empty section list.
    const TINY: &[u8] = b"\x00asm\x0d\x00\x01\x00";

    fn limits() -> Limits {
        Limits {
            memory: "128MiB".to_owned(),
            fuel: 50_000_000,
            epoch_deadline_ms: 5_000,
            max_open_handles: 256,
            max_instances: 8,
            ..Limits::default()
        }
    }

    fn roomy() -> HostCapacity {
        HostCapacity {
            memory_budget_bytes: 4 * 1024 * 1024 * 1024,
            max_instances: 8,
            resident_bytes: 0,
            max_virtual_reservation_bytes: u64::MAX,
        }
    }

    fn item(name: &str, bytes: &[u8]) -> PreloadItem {
        PreloadItem {
            name: name.to_owned(),
            bytes: bytes.to_vec(),
            // A real digest, deliberately: `preload` verifies it, and a
            // fixture with a fake one would fail for the wrong reason.
            digest: content_digest(bytes),
        }
    }

    #[test]
    fn a_valid_component_is_preloaded_with_its_artifact() {
        let report = preload(
            &[item("ok", TINY)],
            &limits(),
            &EngineConfig::default(),
            &roomy(),
        )
        .expect("preload must run");

        assert!(report.is_complete(), "one good component must be ready");
        assert_eq!(report.failures(), 0);
        assert_eq!(report.ready().count(), 1);

        let (_, outcome) = &report.outcomes[0];
        match outcome {
            PreloadOutcome::Compiled { cwasm, took } => {
                assert!(!cwasm.is_empty(), "compilation must produce artifact bytes");
                assert!(
                    *took < Duration::from_mins(1),
                    "compiling 8 bytes took {took:?}, which suggests it did not happen"
                );
            }
            PreloadOutcome::Failed { error } => panic!("expected Compiled, got {error}"),
        }
    }

    /// **The point of the module**: an invalid artifact fails at preload, so it
    /// never reaches a first request.
    #[test]
    fn an_invalid_artifact_fails_at_preload_rather_than_at_first_request() {
        let report = preload(
            &[item("bad", b"not wasm at all")],
            &limits(),
            &EngineConfig::default(),
            &roomy(),
        )
        .expect("the call itself succeeds; the item fails");

        assert_eq!(report.failures(), 1);
        assert!(!report.is_complete());
        let (name, outcome) = &report.outcomes[0];
        assert_eq!(name, "bad");
        assert_eq!(outcome.as_str(), "failed");

        let PreloadOutcome::Failed { error } = outcome else {
            panic!("expected Failed, got {outcome:?}");
        };
        assert_eq!(error.code, ErrorCode::InvalidComponentArtifact);
        assert!(
            error.context.iter().any(|(k, _)| k == "digest"),
            "the digest must be in the context so an operator can find the artifact"
        );
        assert!(error.remediation.is_some(), "a failure needs a remediation");
    }

    /// **Partial success is the only useful outcome.** One bad artifact must not
    /// stop the rest, and the report must let the caller tell them apart.
    #[test]
    fn one_bad_artifact_does_not_stop_the_others() {
        let report = preload(
            &[
                item("good-1", TINY),
                item("bad", b"garbage"),
                item("good-2", TINY),
            ],
            &limits(),
            &EngineConfig::default(),
            &roomy(),
        )
        .expect("preload must run");

        assert_eq!(report.outcomes.len(), 3, "every item must be reported");
        assert_eq!(report.ready().count(), 2);
        assert_eq!(report.failed().count(), 1);

        let names: Vec<&str> = report.ready().map(|(n, _)| n).collect();
        assert_eq!(names, vec!["good-1", "good-2"]);
        assert_eq!(report.failed().next().map(|(n, _)| n), Some("bad"));
    }

    /// `failures()` and `failed().count()` cannot disagree, because the count is
    /// derived rather than stored.
    #[test]
    fn the_failure_count_agrees_with_the_failed_iterator() {
        let report = preload(
            &[
                item("a", b"x"),
                item("b", TINY),
                item("c", b"y"),
                item("d", b"z"),
            ],
            &limits(),
            &EngineConfig::default(),
            &roomy(),
        )
        .expect("runs");

        assert_eq!(report.failures(), report.failed().count());
        assert_eq!(report.failures(), 3);
        assert!(!report.is_complete());
    }

    #[test]
    fn an_empty_set_is_complete_and_reports_nothing() {
        let report = preload(&[], &limits(), &EngineConfig::default(), &roomy()).expect("runs");
        assert!(report.is_complete());
        assert_eq!(report.outcomes.len(), 0);
        assert_eq!(report.slowest(), None);
    }

    /// A set that cannot be admitted at all is a whole-set error, because there
    /// is no per-item outcome to report.
    #[test]
    fn a_set_that_cannot_be_admitted_fails_wholesale() {
        let starved = HostCapacity {
            memory_budget_bytes: 64 * 1024 * 1024,
            max_instances: 8,
            resident_bytes: 128 * 1024 * 1024,
            max_virtual_reservation_bytes: u64::MAX,
        };

        let err = preload(
            &[item("a", TINY)],
            &limits(),
            &EngineConfig::default(),
            &starved,
        )
        .expect_err("nothing can be admitted");
        assert_eq!(err.code, ErrorCode::LimitOutOfRange);
        assert!(
            err.context.iter().any(|(k, _)| k == "items"),
            "the error must say how many items were affected: {err}"
        );
    }

    /// `slowest` is for a deploy report, and must track the actual maximum.
    #[test]
    fn slowest_reports_the_longest_successful_compilation() {
        let report = preload(
            &[item("a", TINY), item("b", TINY)],
            &limits(),
            &EngineConfig::default(),
            &roomy(),
        )
        .expect("runs");

        let (name, took) = report.slowest().expect("two compiled");
        assert!(["a", "b"].contains(&name));
        let max = report
            .outcomes
            .iter()
            .filter_map(|(_, o)| match o {
                PreloadOutcome::Compiled { took, .. } => Some(*took),
                PreloadOutcome::Failed { .. } => None,
            })
            .max()
            .expect("two compiled");
        assert_eq!(took, max, "slowest must be the maximum, not the last");
    }

    /// A set with no successes has no slowest, rather than a zero duration that
    /// reads as "instant".
    #[test]
    fn slowest_is_none_when_nothing_compiled() {
        let report = preload(
            &[item("bad", b"nope")],
            &limits(),
            &EngineConfig::default(),
            &roomy(),
        )
        .expect("runs");
        assert_eq!(report.slowest(), None);
    }

    /// The cache key must be stable across calls, or a write and a read in
    /// different deploys would never agree.
    #[test]
    fn the_cache_key_is_stable_and_content_keyed() {
        let cfg = EngineConfig::default();
        let a = item("a", TINY);
        // Different bytes, so a different digest: the key must follow content.
        let b = item("b", b"\x00asm\x0d\x00\x01\x01");

        assert_eq!(cache_key_for(&a, &cfg), cache_key_for(&a, &cfg), "stable");
        assert_ne!(
            cache_key_for(&a, &cfg),
            cache_key_for(&b, &cfg),
            "different digests must produce different keys"
        );
        assert_eq!(cache_key_for(&a, &cfg).len(), 64, "a sha256 hex digest");
    }

    /// Deterministic mode changes codegen, so it must change the key -- otherwise
    /// a deployment that switched modes would load artifacts compiled under the
    /// other and break the bit-identical replay guarantee (§10.5).
    #[test]
    fn the_cache_key_changes_with_the_engine_configuration() {
        let a = item("a", TINY);
        assert_ne!(
            cache_key_for(&a, &EngineConfig::default()),
            cache_key_for(&a, &EngineConfig::deterministic()),
            "a deterministic engine must not load a non-deterministic artifact"
        );
    }

    #[test]
    fn the_outcome_names_are_bounded_and_distinct() {
        let outcomes = [
            PreloadOutcome::Compiled {
                cwasm: vec![1],
                took: Duration::ZERO,
            },
            PreloadOutcome::Failed {
                error: Box::new(Error::new(ErrorCode::InvalidComponentArtifact, "x")),
            },
        ];
        let mut names = std::collections::BTreeSet::new();
        for o in outcomes {
            assert!(names.insert(o.as_str()), "duplicate: {}", o.as_str());
            assert_eq!(o.is_ready(), o.as_str() == "compiled");
        }
    }

    /// `Debug` must not dump the artifact bytes into a log line.
    #[test]
    fn the_item_debug_does_not_print_the_bytes() {
        // A fixed digest without a "171" substring, so the assertion below
        // tests the byte dump and not the digest's hex.
        let i = PreloadItem {
            name: "a".to_owned(),
            bytes: vec![0xAB_u8; 4096],
            digest: "ab".repeat(32),
        };
        let text = format!("{i:?}");
        assert!(text.contains('a'), "the name must appear");
        assert!(text.contains("4096 B"), "the size must appear");
        assert!(
            !text.contains("171"),
            "raw byte values must not appear: {text}"
        );
    }

    /// **The digest is verified, not trusted.** Bytes accompanied by a digest
    /// that names a different artifact must fail as that item, so a cache
    /// entry is never written under a key that names something else. A caller
    /// that mixes up two artifacts in its own pipeline gets a per-item
    /// failure at deploy, not a poisoned cache at serve time.
    #[test]
    fn a_digest_that_does_not_match_the_bytes_fails_the_item() {
        let mut mismatched = item("swapped", TINY);
        mismatched.digest = "0".repeat(64);
        assert_ne!(
            mismatched.digest,
            content_digest(TINY),
            "the fixture must mismatch"
        );

        let report = preload(&[mismatched], &limits(), &EngineConfig::default(), &roomy())
            .expect("the call itself succeeds; the item fails");

        assert_eq!(report.failures(), 1);
        let (_, outcome) = &report.outcomes[0];
        let PreloadOutcome::Failed { error } = outcome else {
            panic!("a mislabeled artifact must not compile: {outcome:?}");
        };
        assert_eq!(error.code, ErrorCode::ComponentDigestMismatch);
        assert!(
            error.context.iter().any(|(k, _)| k == "digest"),
            "the claimed digest must be in the context: {error}"
        );
        assert!(error.remediation.is_some(), "a failure needs a remediation");
    }

    /// A malformed digest fails on shape, before any hashing: a gigabyte of
    /// bytes with a garbage claim must not pay a SHA-256 first. The echo is
    /// capped, so a huge claim cannot become a huge error.
    #[test]
    fn a_malformed_digest_fails_on_shape_with_a_capped_echo() {
        let mut bad = item("swapped", TINY);
        bad.digest = "x".repeat(10_000);
        let report = preload(&[bad], &limits(), &EngineConfig::default(), &roomy())
            .expect("the call itself succeeds; the item fails");
        assert_eq!(report.failures(), 1);
        let (_, outcome) = &report.outcomes[0];
        let PreloadOutcome::Failed { error } = outcome else {
            panic!("a shapeless digest must not compile: {outcome:?}");
        };
        assert_eq!(error.code, ErrorCode::ComponentDigestMismatch);
        let text = format!("{error:#}");
        assert!(
            !text.contains(&"x".repeat(1000)),
            "the echo must be capped, not the whole claim: {text:.200}"
        );
        assert!(
            text.contains("10000"),
            "the cap must still say how long the claim was: {text:.200}"
        );
    }

    /// Digests are lowercase by convention: an uppercase spelling of the
    /// right hash still fails, because two spellings of one digest would
    /// compare unequal downstream.
    #[test]
    fn an_uppercase_digest_is_not_canonical() {
        assert!(!digest_shape_valid(&content_digest(TINY).to_uppercase()));
        assert!(digest_shape_valid(&content_digest(TINY)));
    }
}
