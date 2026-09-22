// SPDX-License-Identifier: Apache-2.0

//! The `§9.1` methodology, as a type rather than a paragraph.
//!
//! # Why this module exists in this shape
//!
//! `§9.1` ends with a sentence that decides the design of this whole crate:
//!
//! > **Methodology requirements** (published with every result): pinned hardware
//! > listed by model; pinned OS and kernel; pinned toolchain versions; warmup
//! > procedure stated; percentiles, not averages; concurrency levels disclosed;
//! > three repetitions with variance; the benchmark harness itself open source;
//! > and a "what this does not measure" section. **A benchmark without these is
//! > marketing, and we should not publish it.**
//!
//! Three words in that paragraph are load-bearing, and each one rules out an
//! easier implementation:
//!
//! * **"published with every result"** — not "documented once". A methodology
//!   page satisfies the letter and misses the requirement: the fifth report can
//!   omit its warmup procedure and the page still exists. So the elements are
//!   fields of the *result*, not of a document.
//! * **"percentiles, not averages"** — a prohibition, and the cheapest way to
//!   honour a prohibition is for the forbidden thing not to exist. See
//!   [`Distribution`](crate::stats::Distribution), which has no `mean`.
//! * **"we should not publish it"** — the consequence is refusal, so the type
//!   must be **unconstructible** without the elements. A `Debug`-time warning or
//!   a lint would be advice; a missing constructor is enforcement.
//!
//! # What was rejected
//!
//! **A `bench/` directory of shell scripts plus a `BENCHMARKING.md`.** This is the
//! obvious approach and it was rejected because **prose cannot fail**. A
//! methodology document that drifts from what the harness actually does is this
//! repository's most-recorded defect shape — *a control believed live that is
//! not* — and it is undetectable precisely because nothing executes the prose.
//! The checker in `tools/check_bench_contract.py` can only exist because the
//! contract is data.
//!
//! **Optional fields plus a `validate()` method.** Rejected because it moves the
//! failure from compile time to run time for no benefit: there is no legitimate
//! caller that wants a result missing its concurrency level. A `Result` here
//! would be an error path that only ever fires on programmer error, which is what
//! a type is for.
//!
//! **A `Criterion`-based harness.** Rejected for `PERF-001` specifically: the
//! budget rows in `§9.2` are stated against *a running server over a socket* at a
//! *disclosed concurrency*, and `Criterion` measures in-process function calls
//! with no concurrency concept. `Criterion` is the right tool for a microbenchmark
//! and this harness still accommodates one, but the methodology is about the
//! published claim, and that claim is made about a served application.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// A benchmark's name, restricted to the ten `§9.1` rows plus explicitly
/// registered extensions.
///
/// # Why this is a closed enum and not a `String`
///
/// `§9.1` names **ten** benchmarks and `§9.2` sets budgets against "the reference
/// app". A free-form name means a typo (`tailp9`, `crypto1`) produces a result
/// that silently belongs to no row, and a report that renders it beside the real
/// ones. Measured consequence of the alternative, from this project's own history:
/// a metric label that could take an unbounded value produced 1 000 series from
/// 1 000 invented inputs before `SRV-020` made the label an enum.
///
/// [`BenchmarkName::Other`] exists because `PERF-002` may legitimately add a
/// workload that `§9.1` does not name. It is deliberately **not** a wildcard: it
/// carries the name it was given, so a report can still group by it, and the
/// `§9.2` budget table — which is keyed by the ten — cannot accidentally match it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BenchmarkName {
    /// `hello` — empty HTTP response. Raw framework + runtime overhead.
    Hello,
    /// `json` — serialize a 1 KB object. Serialization + ABI.
    Json,
    /// `route` — 100 routes, path params.
    Route,
    /// `db` — 10 queries against Postgres. **See the caveat in the module docs for
    /// [`NonClaims`]: the host has no `qqq:sql` implementation, so this row
    /// currently measures an in-guest store, not a database round trip.**
    Db,
    /// `crypto` — 1 KB SHA-256 ×10 000.
    Crypto,
    /// `template` — render a 100-row HTML table.
    Template,
    /// `cpu` — prime sieve / matrix multiply.
    Cpu,
    /// `multi` — saturate 8 cores.
    Multi,
    /// `tailp99` — 30-minute sustained load.
    TailP99,
    /// `cold` — instantiate and serve once.
    Cold,
    /// A workload that `§9.1` does not name, carried by name so it stays
    /// groupable in a report and can never match a `§9.2` budget row.
    Other(String),
}

impl BenchmarkName {
    /// Every name `§9.1` specifies, in the order the Proposal lists them.
    ///
    /// # Why the order is preserved rather than sorted
    ///
    /// A report that lists the ten in Proposal order is diffable against `§9.1`
    /// by eye, which is how a reader checks that all ten were run. Alphabetical
    /// order would be stable too, but it would hide a *missing* row: a reader
    /// scanning for `tailp99` finds its absence faster in a familiar order.
    ///
    /// [`BenchmarkName::Other`] is absent by construction — it is not one of the
    /// ten, and [`Self::is_specification_benchmark`] is the predicate that says so.
    #[must_use]
    pub fn all_specified() -> [Self; 10] {
        [
            Self::Hello,
            Self::Json,
            Self::Route,
            Self::Db,
            Self::Crypto,
            Self::Template,
            Self::Cpu,
            Self::Multi,
            Self::TailP99,
            Self::Cold,
        ]
    }

    /// Whether this is one of the ten `§9.1` names, as opposed to an extension.
    ///
    /// This is the predicate a completeness check uses: `PERF-002` is complete
    /// when all ten of these are present, and a report containing only `Other`
    /// variants is complete by no reading of `§9.1`.
    #[must_use]
    pub fn is_specification_benchmark(&self) -> bool {
        !matches!(self, Self::Other(_))
    }

    /// The name as it appears in `§9.1` and in a report.
    ///
    /// # Why the return type is `Cow<'_, str>` and not `&str`
    ///
    /// The ten specification names are `'static` string literals, but
    /// [`BenchmarkName::Other`] owns a `String`. A plain `&str` return would tie
    /// the lifetime to `self`, which compiles and then makes the method
    /// **unusable on an owned value** — `all_specified().into_iter().map(as_str)`
    /// fails with *"cannot return value referencing function parameter"*. That was
    /// this method's first signature, and the failure is recorded because it is
    /// the rule this project states as *an error reported at a call site is
    /// usually a mistake in the signature*: the fix is here, not at the call site.
    ///
    /// `Cow` states the truth — borrowed for the ten, owned for an extension —
    /// without forcing an allocation in the common case.
    #[must_use]
    pub fn as_str(&self) -> std::borrow::Cow<'_, str> {
        use std::borrow::Cow;
        match self {
            Self::Hello => Cow::Borrowed("hello"),
            Self::Json => Cow::Borrowed("json"),
            Self::Route => Cow::Borrowed("route"),
            Self::Db => Cow::Borrowed("db"),
            Self::Crypto => Cow::Borrowed("crypto"),
            Self::Template => Cow::Borrowed("template"),
            Self::Cpu => Cow::Borrowed("cpu"),
            Self::Multi => Cow::Borrowed("multi"),
            Self::TailP99 => Cow::Borrowed("tailp99"),
            Self::Cold => Cow::Borrowed("cold"),
            Self::Other(name) => Cow::Borrowed(name.as_str()),
        }
    }

    /// Parse a benchmark name, mapping the ten specification names and nothing
    /// else onto their variants.
    ///
    /// An unrecognised name becomes [`BenchmarkName::Other`] rather than an error,
    /// because `PERF-002` may add a workload and a harness that refused to run it
    /// would be a harness that has to be edited before it can measure something
    /// new. The safety is in [`Self::is_specification_benchmark`], which keeps an
    /// extension out of the `§9.2` budget table.
    #[must_use]
    pub fn parse(name: &str) -> Self {
        Self::all_specified()
            .into_iter()
            .find(|candidate| candidate.as_str() == name)
            .unwrap_or_else(|| Self::Other(name.to_owned()))
    }
}

impl fmt::Display for BenchmarkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

/// The exact hardware and software a result was measured on.
///
/// # Why this is mandatory and why it carries no default
///
/// `§9.1` requires "pinned hardware listed by **model**; pinned OS and kernel;
/// pinned toolchain versions". A benchmark number without these is not comparable
/// to anything, including another run of the same suite — which is exactly the
/// failure `§9.1` calls marketing.
///
/// There is deliberately **no `Default` implementation**. A default would be a
/// value nobody chose, and a result carrying an unchosen environ would be a false
/// claim with the appearance of a filled-in field. The same reasoning as
/// `SRV-020`'s "`None` means unlimited; zero means the smallest limit": a value
/// that looks like a measurement and is not one is worse than a missing field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Environment {
    /// The CPU model, as a vendor string names it — `"AMD Ryzen 9 7950X"`, not
    /// `"16-core"`. Core counts alone do not identify a machine.
    pub cpu_model: String,
    /// Physical core count available to the run.
    ///
    /// Recorded separately from the model because a benchmark can be pinned to a
    /// subset of cores, and a result measured on four of sixteen must say so.
    pub physical_cores: u32,
    /// Total system memory in bytes.
    pub memory_bytes: u64,
    /// Operating system and version — `"Ubuntu 24.04.1 LTS"`.
    pub os: String,
    /// Kernel version — `"6.8.0-45-generic"`.
    ///
    /// Separate from [`Self::os`] because kernel version is where scheduling and
    /// network-stack behaviour changes, and `§9.1` names it separately.
    pub kernel: String,
    /// The toolchain versions, keyed by tool.
    ///
    /// A map rather than a fixed struct because the set differs by language —
    /// Rust needs `rustc` and `cargo`, `PERF-*`'s future TypeScript comparison
    /// needs `node` — and inventing empty fields for absent tools would be the
    /// placeholder this project refuses.
    pub toolchains: BTreeMap<String, String>,
}

impl Environment {
    /// Build an environment record, refusing an empty required field.
    ///
    /// # Errors
    ///
    /// Returns the name of the first empty field. An empty model, OS or kernel
    /// satisfies the struct and not the requirement, and `§9.1` asks for the
    /// values, not for the fields.
    pub fn new(
        cpu_model: impl Into<String>,
        physical_cores: u32,
        memory_bytes: u64,
        os: impl Into<String>,
        kernel: impl Into<String>,
        toolchains: BTreeMap<String, String>,
    ) -> Result<Self, &'static str> {
        let candidate = Self {
            cpu_model: cpu_model.into(),
            physical_cores,
            memory_bytes,
            os: os.into(),
            kernel: kernel.into(),
            toolchains,
        };

        // The vacuity check. A struct with empty strings is "present" to every
        // structural test and states nothing -- `§O-128`'s shape, and the reason
        // this is a constructor and not a literal.
        if candidate.cpu_model.trim().is_empty() {
            return Err("cpu_model");
        }
        if candidate.os.trim().is_empty() {
            return Err("os");
        }
        if candidate.kernel.trim().is_empty() {
            return Err("kernel");
        }
        if candidate.physical_cores == 0 {
            return Err("physical_cores");
        }
        if candidate.memory_bytes == 0 {
            return Err("memory_bytes");
        }
        if candidate.toolchains.is_empty() {
            return Err("toolchains");
        }
        if candidate
            .toolchains
            .iter()
            .any(|(tool, version)| tool.trim().is_empty() || version.trim().is_empty())
        {
            return Err("toolchains (empty key or value)");
        }
        Ok(candidate)
    }
}

/// How a run was warmed up before its samples were taken.
///
/// # Why "none" is a variant rather than an absent field
///
/// `§9.1` requires the warmup procedure be **stated**. The most common procedure
/// is no warmup — a cold-start benchmark must not warm anything, or it would
/// measure the opposite of what its row claims. Modelling that as `Option::None`
/// makes "we deliberately did not warm up" indistinguishable from "we forgot to
/// record it", and the second is the defect. An explicit
/// [`Warmup::None`] with a required justification makes the deliberate case a
/// decision that was written down, which is what "stated" means.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Warmup {
    /// No warmup was performed. The `justification` is required and must be
    /// non-empty: this is correct for `cold` and wrong for everything else.
    None {
        /// Why no warmup. A cold-start row explains itself here; anything else
        /// needs a reason.
        ///
        /// # Why `&'static str` and not `String`
        ///
        /// It was a `String`, and making `Workload::ALL` a `const` array exposed
        /// the cost: `String::from` is **not const-callable** — verified with a
        /// standalone probe, which rustc rejects in a const context with *"cannot
        /// call non-const associated function"*. So a `const` table of workloads
        /// could not carry an owned justification.
        ///
        /// `&'static str` is also the more honest type. This is explanatory text a
        /// programmer writes in the source; it is never assembled at run time from
        /// user input, and a dynamically built justification would be a strange
        /// thing to store in a benchmark's methodology. The borrow makes `Warmup`
        /// cheaper to copy and lets the whole specification live in read-only
        /// # Why `Cow<'static, str>` and not `String` or `&'static str`
        ///
        /// It was a `String`, and making `Workload::ALL` a `const` array exposed
        /// the cost: `String::from` is **not const-callable** — verified with a
        /// standalone probe, which rustc rejects in a const context with *"cannot
        /// call non-const associated function"*. So a `const` table of workloads
        /// could not carry an owned justification.
        ///
        /// A bare `&'static str` then failed a *different* way, and the failure is
        /// worth recording because it is a real constraint rather than a
        /// workaround: `#[derive(Deserialize)]` **cannot** produce a `&'static str`
        /// from arbitrary input, because the borrowed data would have to outlive
        /// the deserializer. Rust rejected the derive with *"requires that `'de`
        /// must outlive `'static`"* — correctly. A type able to fabricate a
        /// `'static` borrow from parsed bytes would be unsound.
        ///
        /// `Cow<'static, str>` is the type that is true in both directions: a
        /// literal written in the source stays borrowed with no allocation, and a
        /// value that genuinely came from deserialization is owned. That is exactly
        /// the distinction the two failures were drawing, so the type now states it.
        justification: std::borrow::Cow<'static, str>,
    },
    /// A fixed number of iterations were discarded before sampling began.
    Discard {
        /// How many iterations were run and thrown away.
        iterations: u32,
    },
    /// The run was warmed for a fixed duration before sampling began.
    Duration {
        /// Milliseconds of warmup.
        millis: u64,
    },
}

impl Warmup {
    /// Whether this warmup is the deliberate no-warmup case.
    #[must_use]
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None { .. })
    }

    /// A one-line rendering for a report, which is what `§9.1` asks to publish.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::None { justification } => format!("none ({justification})"),
            Self::Discard { iterations } => format!("discard {iterations} iterations"),
            Self::Duration { millis } => format!("{millis} ms duration"),
        }
    }
}

/// What the workload did **not** measure.
///
/// # Why `§9.1`'s ninth requirement is the one that matters most here
///
/// The other eight elements describe the measurement. This one describes its
/// limits, and it is the element a reader is least able to reconstruct and most
/// able to be misled by. `§9.1` names it for exactly that reason.
///
/// It is required, and it must be non-empty. A benchmark with genuinely nothing
/// to disclaim would state that as a [`NonClaims::unqualified`] with its reason —
/// which is a claim in its own right and should be rare.
///
/// **The `db` row is why this type is not optional.** The host has no `qqq:sql`
/// implementation (`§O-155`), so the `db` workload measures a validated write and
/// an in-guest map lookup over a per-request store — **not** a Postgres round
/// trip. That caveat was recorded in a checklist entry and an observation, both
/// of which a future reader may never open. As a required field on the result, it
/// cannot be omitted: a `db` result that does not carry the disclaimer does not
/// compile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NonClaims {
    /// One or more specific things this result does not show.
    Qualified {
        /// The disclaimers. Must be non-empty.
        items: Vec<String>,
    },
    /// The result is claimed to be unqualified, with the reason it is safe to do so.
    ///
    /// The `reason` is required precisely because "nothing to disclaim" is a
    /// strong assertion. Making it cost a sentence is the right friction.
    Unqualified {
        /// Why this result needs no disclaimer.
        reason: String,
    },
}

impl NonClaims {
    /// Build a qualified non-claim set, refusing an empty or blank list.
    ///
    /// # Errors
    ///
    /// Returns an error if `items` is empty or contains only blank strings. An
    /// empty list here is the vacuity failure this project refuses everywhere
    /// else: it satisfies "has a `NonClaims`" while stating nothing.
    pub fn qualified(
        items: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, &'static str> {
        let items: Vec<String> = items.into_iter().map(Into::into).collect();
        if items.is_empty() || items.iter().all(|item| item.trim().is_empty()) {
            return Err("NonClaims::Qualified requires at least one non-blank item");
        }
        Ok(Self::Qualified { items })
    }

    /// Build an unqualified claim, refusing a blank reason.
    ///
    /// # Errors
    ///
    /// Returns an error if `reason` is blank.
    pub fn unqualified(reason: impl Into<String>) -> Result<Self, &'static str> {
        let reason = reason.into();
        if reason.trim().is_empty() {
            return Err("NonClaims::Unqualified requires a non-blank reason");
        }
        Ok(Self::Unqualified { reason })
    }

    /// How many disclaimers this carries. Zero means the unqualified case.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Qualified { items } => items.len(),
            Self::Unqualified { .. } => 0,
        }
    }

    /// Whether this carries no disclaimers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The `§9.1` methodology, captured as a value.
///
/// Every field is required and there is no `Default`, because `§9.1`'s
/// requirement is that these are **published with every result** — a defaulted
/// methodology is a methodology nobody chose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Methodology {
    /// Where the numbers were produced. Hardware, OS, kernel, toolchains.
    pub environment: Environment,
    /// How the run was warmed, or why it was not.
    pub warmup: Warmup,
    /// How many requests were in flight at once.
    ///
    /// Required and explicit because `§9.1` says "concurrency levels disclosed",
    /// and because it is the single parameter that changes a throughput figure
    /// most. A `None` here would be a missing disclosure dressed as a value;
    /// concurrency 1 is [`Concurrency::Sequential`], which is a different fact.
    pub concurrency: Concurrency,
    /// How many independent repetitions were performed.
    ///
    /// `§9.1` requires "three repetitions with variance", and
    /// [`Methodology::new`] refuses fewer than three. The constant
    /// [`Methodology::REQUIRED_REPETITIONS`] is the number, named so a test can
    /// state the rule rather than spell `3` in two places.
    pub repetitions: u32,
    /// What this result does not measure. Required; see [`NonClaims`].
    pub non_claims: NonClaims,
    /// Where the harness source lives, so the claim is auditable.
    ///
    /// `§9.1` requires "the benchmark harness itself open source". A URL rather
    /// than a bool: "yes it is open source" is unfalsifiable, and a reader who
    /// wants to check can follow a link.
    pub harness_source: String,
}

impl Methodology {
    /// The number of repetitions `§9.1` requires.
    ///
    /// Three, from "three repetitions with variance". Named rather than inlined
    /// so the rule has a place to be stated and a test has something to assert
    /// against — the reason `§O-124` gives for extracting a named predicate from
    /// an inline conditional.
    pub const REQUIRED_REPETITIONS: u32 = 3;

    /// Assemble a methodology, enforcing every count and emptiness rule `§9.1`
    /// implies but does not spell out.
    ///
    /// # Errors
    ///
    /// Returns a [`MethodologyError`] naming the violated rule. Each rule exists
    /// because the shape it rejects satisfies the *fields* of `§9.1` while
    /// violating its *requirement*:
    ///
    /// * fewer than three repetitions — "three repetitions with variance";
    /// * a [`Warmup::None`] with a blank justification — "procedure **stated**";
    /// * a blank [`harness_source`](Self::harness_source) — "the harness itself
    ///   open source" means a locatable artifact;
    /// * a [`Warmup::Discard`] of zero iterations, or a [`Warmup::Duration`] of
    ///   zero milliseconds, both of which describe no warmup while claiming one.
    pub fn new(
        environment: Environment,
        warmup: Warmup,
        concurrency: Concurrency,
        repetitions: u32,
        non_claims: NonClaims,
        harness_source: impl Into<String>,
    ) -> Result<Self, MethodologyError> {
        let harness_source = harness_source.into();

        if repetitions < Self::REQUIRED_REPETITIONS {
            return Err(MethodologyError::TooFewRepetitions {
                given: repetitions,
                required: Self::REQUIRED_REPETITIONS,
            });
        }
        if harness_source.trim().is_empty() {
            return Err(MethodologyError::BlankHarnessSource);
        }
        if let Warmup::None { justification } = &warmup {
            if justification.trim().is_empty() {
                return Err(MethodologyError::UnjustifiedNoWarmup);
            }
        }
        // Both zero-valued warmups mean the same thing: the caller described a
        // warmup that does no work. Clippy is right that two arms with identical
        // bodies should be one -- and the single arm reads better, because the
        // *reason* they are the same error is worth stating once.
        match &warmup {
            Warmup::Discard { iterations: 0 } | Warmup::Duration { millis: 0 } => {
                return Err(MethodologyError::EmptyWarmup);
            }
            Warmup::None { .. } | Warmup::Discard { .. } | Warmup::Duration { .. } => {}
        }

        Ok(Self {
            environment,
            warmup,
            concurrency,
            repetitions,
            non_claims,
            harness_source,
        })
    }
}

/// A methodology that violates one of `§9.1`'s requirements.
///
/// # Why this is its own type and not a `&'static str`
///
/// Each variant is a *distinct rule*, and a test can assert on the specific one.
/// A single string error would let a test assert only that construction failed,
/// which passes when the wrong rule fires — the failure mode `§O-149` records.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MethodologyError {
    /// Fewer than [`Methodology::REQUIRED_REPETITIONS`] repetitions were given.
    TooFewRepetitions {
        /// What the caller supplied.
        given: u32,
        /// What `§9.1` requires.
        required: u32,
    },
    /// A [`Warmup::None`] was given without a reason.
    UnjustifiedNoWarmup,
    /// A warmup was described that discards nothing and lasts no time.
    EmptyWarmup,
    /// [`Methodology::harness_source`] was blank.
    BlankHarnessSource,
}

impl fmt::Display for MethodologyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFewRepetitions { given, required } => write!(
                f,
                "§9.1 requires {required} repetitions with variance; {given} given"
            ),
            Self::UnjustifiedNoWarmup => f.write_str(
                "§9.1 requires the warmup procedure be stated; \
                 Warmup::None needs a non-blank justification",
            ),
            Self::EmptyWarmup => f.write_str(
                "a warmup that discards zero iterations or runs zero milliseconds \
                 describes no warmup while claiming one",
            ),
            Self::BlankHarnessSource => f.write_str(
                "§9.1 requires the harness be open source; harness_source must name where it is",
            ),
        }
    }
}

impl std::error::Error for MethodologyError {}

/// How many requests were in flight during the measurement.
///
/// # Why this is an enum and not a `u32`
///
/// `§9.1` requires concurrency levels be **disclosed**. `u32` alone cannot
/// distinguish "one at a time" from "we did not record how many", and the second
/// is the disclosure failure. A three-variant enum makes every legal state
/// nameable and leaves no room for an unrecorded one:
///
/// * [`Sequential`](Self::Sequential) is concurrency 1 and is *stated*, not
///   defaulted — a latency measurement is usually taken this way and a throughput
///   measurement never is;
/// * [`Fixed`](Self::Fixed) is the ordinary load-test case;
/// * [`Saturating`](Self::Saturating) is `§9.1`'s `multi` row, "saturate 8 cores",
///   where the interesting number is the machine's capacity rather than a chosen
///   figure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Concurrency {
    /// One request at a time, awaited to completion.
    Sequential,
    /// A stated fixed number of concurrent requests.
    Fixed {
        /// Connections held open simultaneously.
        connections: u32,
    },
    /// Enough load to saturate the available cores.
    Saturating {
        /// The core count the harness targeted. Recorded because "saturating"
        /// means nothing without the machine it saturated.
        cores: u32,
    },
}

impl Concurrency {
    /// The number of concurrent requests, where one is defined.
    ///
    /// [`Saturating`](Self::Saturating) returns `None`: the point of that variant
    /// is that the number was not chosen by the harness, so reporting one would
    /// invent a figure. `None` here is a true statement, unlike `Some(0)` or a
    /// placeholder.
    #[must_use]
    pub fn level(&self) -> Option<u32> {
        match self {
            Self::Sequential => Some(1),
            Self::Fixed { connections } => Some(*connections),
            Self::Saturating { .. } => None,
        }
    }

    /// A one-line rendering for a report.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Sequential => "1 (sequential)".to_owned(),
            Self::Fixed { connections } => format!("{connections} connections"),
            Self::Saturating { cores } => format!("saturating {cores} cores"),
        }
    }
}

/// Whether a run was pinned to a subset of the machine, and to what.
///
/// # Why this is separate from [`Environment`]
///
/// [`Environment`] describes the machine; this describes the **allocation of it
/// to this run**. `§9.2` states several budgets "at 10k RPS" and "8 cores", so a
/// result measured on a machine with sixteen cores but pinned to four is a
/// different claim from one that used all sixteen — and `§9.1`'s "pinned hardware
/// listed by model" is satisfied by the first while the second is the one that
/// matters for a like-for-like comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Pinning {
    /// The run used the whole machine, unrestrained.
    ///
    /// The default, and the honest one: a harness that did not confine the run
    /// should say so rather than guess that it did.
    #[default]
    Unpinned,
    /// The run was restricted, and here is how.
    Pinned {
        /// The mechanism — `"taskset 0-3"`, `"cgroup cpuset"`, `"docker --cpuset-cpus"`.
        ///
        /// A free string because the mechanisms differ by platform and the fact
        /// that matters is which one was used, not that it belongs to a fixed set.
        mechanism: String,
        /// The cores the run actually had, if it was confined to specific ones.
        cores: Option<u32>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Environment {
        Environment::new(
            "AMD Ryzen 9 7950X",
            16,
            64 * 1024 * 1024 * 1024,
            "Ubuntu 24.04.1 LTS",
            "6.8.0-45-generic",
            BTreeMap::from([("rustc".to_owned(), "1.98.0".to_owned())]),
        )
        .expect("the fixture must be valid")
    }

    fn non_claims() -> NonClaims {
        NonClaims::qualified(["this is a fixture"]).expect("non-blank")
    }

    // -- BenchmarkName ------------------------------------------------------

    #[test]
    fn the_ten_specification_benchmarks_are_exactly_the_ones_in_the_proposal() {
        // Pinned against §9.1's table by name, because a variant added or removed
        // silently changes what "all ten were run" means.
        //
        // `into_iter` rather than `iter`: `all_specified` returns an owned array,
        // so borrowing it would borrow a temporary that dies at the end of the
        // statement.
        let names: Vec<String> = BenchmarkName::all_specified()
            .into_iter()
            .map(|name| name.as_str().into_owned())
            .collect();
        assert_eq!(
            names,
            vec![
                "hello", "json", "route", "db", "crypto", "template", "cpu", "multi", "tailp99",
                "cold"
            ]
        );
    }

    #[test]
    fn every_specified_name_is_a_specification_benchmark() {
        for name in BenchmarkName::all_specified() {
            assert!(
                name.is_specification_benchmark(),
                "{name} must count as a specification benchmark"
            );
        }
    }

    #[test]
    fn an_extension_is_not_a_specification_benchmark() {
        // The property that keeps a PERF-002 extension out of the §9.2 budget
        // table. Without it, a workload named "hello2" would be a new row.
        assert!(!BenchmarkName::Other("hello2".to_owned()).is_specification_benchmark());
    }

    #[test]
    fn parse_maps_the_ten_and_keeps_everything_else_by_name() {
        for name in BenchmarkName::all_specified() {
            assert_eq!(BenchmarkName::parse(name.as_str().as_ref()), name);
        }
        // A near-miss must NOT resolve to the real row: `tailp9` is a different
        // name, and treating it as `tailp99` would attribute a measurement to a
        // §9.2 budget it was never taken against.
        assert_ne!(BenchmarkName::parse("tailp9"), BenchmarkName::TailP99);
        assert_eq!(
            BenchmarkName::parse("tailp9"),
            BenchmarkName::Other("tailp9".to_owned())
        );
    }

    #[test]
    fn a_name_round_trips_through_serde() {
        for name in BenchmarkName::all_specified() {
            let json = serde_json::to_string(&name).expect("serialisable");
            let back: BenchmarkName = serde_json::from_str(&json).expect("deserialisable");
            assert_eq!(back, name, "round trip failed for {name}");
        }
    }

    // -- Environment --------------------------------------------------------

    #[test]
    fn an_environment_with_a_blank_field_is_refused() {
        // Each of these satisfies the struct and violates §9.1, which asks for
        // the VALUES. A blank string is present to every structural check.
        let cases: Vec<(&str, Result<Environment, &'static str>)> = vec![
            (
                "blank cpu_model",
                Environment::new(
                    "",
                    16,
                    1,
                    "os",
                    "k",
                    BTreeMap::from([("r".to_owned(), "1".to_owned())]),
                ),
            ),
            (
                "blank os",
                Environment::new(
                    "cpu",
                    16,
                    1,
                    "   ",
                    "k",
                    BTreeMap::from([("r".to_owned(), "1".to_owned())]),
                ),
            ),
            (
                "blank kernel",
                Environment::new(
                    "cpu",
                    16,
                    1,
                    "os",
                    "",
                    BTreeMap::from([("r".to_owned(), "1".to_owned())]),
                ),
            ),
            (
                "zero cores",
                Environment::new(
                    "cpu",
                    0,
                    1,
                    "os",
                    "k",
                    BTreeMap::from([("r".to_owned(), "1".to_owned())]),
                ),
            ),
            (
                "zero memory",
                Environment::new(
                    "cpu",
                    16,
                    0,
                    "os",
                    "k",
                    BTreeMap::from([("r".to_owned(), "1".to_owned())]),
                ),
            ),
            (
                "no toolchains",
                Environment::new("cpu", 16, 1, "os", "k", BTreeMap::new()),
            ),
            (
                "a toolchain with a blank version",
                Environment::new(
                    "cpu",
                    16,
                    1,
                    "os",
                    "k",
                    BTreeMap::from([("rustc".to_owned(), "  ".to_owned())]),
                ),
            ),
        ];

        for (label, outcome) in cases {
            assert!(outcome.is_err(), "{label} must be refused");
        }
    }

    #[test]
    fn a_complete_environment_is_accepted() {
        // The control. Without it, every assertion above would still pass if the
        // constructor rejected everything.
        assert!(Environment::new(
            "AMD Ryzen 9 7950X",
            16,
            1,
            "Ubuntu 24.04.1 LTS",
            "6.8.0-45-generic",
            BTreeMap::from([("rustc".to_owned(), "1.98.0".to_owned())])
        )
        .is_ok());
    }

    // -- Warmup -------------------------------------------------------------

    #[test]
    fn a_discard_of_zero_iterations_is_not_a_warmup() {
        let err = Methodology::new(
            env(),
            Warmup::Discard { iterations: 0 },
            Concurrency::Sequential,
            3,
            non_claims(),
            "https://github.com/RatioArtificiosa/QQQ",
        );
        assert_eq!(err, Err(MethodologyError::EmptyWarmup));
    }

    #[test]
    fn a_duration_of_zero_millis_is_not_a_warmup() {
        let err = Methodology::new(
            env(),
            Warmup::Duration { millis: 0 },
            Concurrency::Sequential,
            3,
            non_claims(),
            "https://github.com/RatioArtificiosa/QQQ",
        );
        assert_eq!(err, Err(MethodologyError::EmptyWarmup));
    }

    #[test]
    fn an_unjustified_no_warmup_is_refused() {
        // §9.1 says the procedure is "stated". `None` is a legitimate procedure
        // for `cold`; `None` with no reason is an omission wearing a variant.
        let err = Methodology::new(
            env(),
            Warmup::None {
                justification: std::borrow::Cow::Borrowed("   "),
            },
            Concurrency::Sequential,
            3,
            non_claims(),
            "https://github.com/RatioArtificiosa/QQQ",
        );
        assert_eq!(err, Err(MethodologyError::UnjustifiedNoWarmup));
    }

    #[test]
    fn a_justified_no_warmup_is_accepted() {
        // The control for the test above. A cold-start row is the real case.
        assert!(Methodology::new(
            env(),
            Warmup::None {
                justification: std::borrow::Cow::Borrowed(
                    "cold start: warming would measure the opposite",
                ),
            },
            Concurrency::Sequential,
            3,
            non_claims(),
            "https://github.com/RatioArtificiosa/QQQ",
        )
        .is_ok());
    }

    // -- Methodology --------------------------------------------------------

    #[test]
    fn fewer_than_three_repetitions_is_refused() {
        for given in [0_u32, 1, 2] {
            let outcome = Methodology::new(
                env(),
                Warmup::Discard { iterations: 100 },
                Concurrency::Fixed { connections: 8 },
                given,
                non_claims(),
                "https://github.com/RatioArtificiosa/QQQ",
            );
            assert_eq!(
                outcome,
                Err(MethodologyError::TooFewRepetitions { given, required: 3 }),
                "{given} repetitions must be refused"
            );
        }
    }

    #[test]
    fn exactly_three_repetitions_is_the_boundary_and_is_accepted() {
        // The boundary case: 3 is required, so 3 must pass. An off-by-one using
        // `<=` would reject the one value §9.1 demands.
        assert!(Methodology::new(
            env(),
            Warmup::Discard { iterations: 100 },
            Concurrency::Fixed { connections: 8 },
            Methodology::REQUIRED_REPETITIONS,
            non_claims(),
            "https://github.com/RatioArtificiosa/QQQ",
        )
        .is_ok());
    }

    #[test]
    fn a_blank_harness_source_is_refused() {
        let err = Methodology::new(
            env(),
            Warmup::Discard { iterations: 100 },
            Concurrency::Fixed { connections: 8 },
            3,
            non_claims(),
            "  ",
        );
        assert_eq!(err, Err(MethodologyError::BlankHarnessSource));
    }

    // -- Concurrency --------------------------------------------------------

    #[test]
    fn sequential_states_its_level_and_saturating_refuses_to_invent_one() {
        assert_eq!(Concurrency::Sequential.level(), Some(1));
        assert_eq!(Concurrency::Fixed { connections: 64 }.level(), Some(64));
        // Saturating deliberately has no chosen number; reporting one would
        // invent a figure the harness never selected.
        assert_eq!(Concurrency::Saturating { cores: 8 }.level(), None);
    }

    #[test]
    fn zero_connections_is_a_fixed_concurrency_of_zero() {
        // Documented rather than prevented: `Fixed { connections: 0 }` is a
        // caller error, but it is NOT silently equal to `Sequential` -- the two
        // describe different things and a report must be able to tell them apart.
        // Collapsing zero into "sequential" would let a run that sent no requests
        // at all be published as a sequential measurement.
        let fixed = Concurrency::Fixed { connections: 0 };
        assert_ne!(fixed, Concurrency::Sequential);
        assert_eq!(fixed.level(), Some(0));
    }

    // -- NonClaims ----------------------------------------------------------

    #[test]
    fn an_empty_non_claim_list_is_refused() {
        // The vacuity case: it satisfies "has a NonClaims" while stating nothing.
        assert!(NonClaims::qualified(Vec::<String>::new()).is_err());
        assert!(NonClaims::qualified(["", "  "]).is_err());
    }

    #[test]
    fn an_unqualified_claim_needs_a_reason() {
        assert!(NonClaims::unqualified("").is_err());
        assert!(NonClaims::unqualified("   ").is_err());
        assert!(NonClaims::unqualified("a pure function with no I/O").is_ok());
    }

    #[test]
    fn a_real_disclaimer_is_counted() {
        let claims = NonClaims::qualified([
            "does not measure a Postgres round trip",
            "does not include network I/O",
        ])
        .expect("non-blank");
        assert_eq!(claims.len(), 2);
        assert!(!claims.is_empty());
        assert!(NonClaims::unqualified("nothing")
            .expect("non-blank")
            .is_empty());
    }
}
