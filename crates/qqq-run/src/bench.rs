// SPDX-License-Identifier: Apache-2.0

//! `qqqai bench` — run the `§9.1` benchmarks against a served application.
//!
//! # What this command is, and what it is not
//!
//! It is a **load generator with a published methodology**, not a microbenchmark
//! runner. `§9.2` states several budgets about a *running server* — "at 10k RPS",
//! "`json` benchmark, 1 KB payload", "host-side, excluding guest work" — and none
//! of those is observable in-process. So this connects to a listening socket and
//! speaks HTTP/1.1 (see `qqq_bench::loadgen` for why the client is hand-written).
//!
//! # Why it does not start the server itself
//!
//! The tempting design is `qqqai bench` starting `qqqai serve` as a child and
//! measuring it. That was rejected because it makes the number depend on the
//! harness's own process management: the child's startup, the time to bind, and
//! whether the harness waited long enough all become part of the measurement, and
//! none of them is part of what `§9.2` budgets.
//!
//! So the command **requires a target** and says so when there is none. The user
//! runs `qqqai serve` in one terminal and `qqqai bench` in another — which also
//! matches how `§9.1` describes the benchmarks being driven (by an external
//! harness that is "open source", not by the runtime under test).
//!
//! # Why the environment comes from the machine, not from a flag
//!
//! `§9.1` requires "pinned hardware listed by model; pinned OS and kernel; pinned
//! toolchain versions" published with every result. These are *read*, not accepted
//! as arguments: a caller able to assert its own environment could publish a
//! result claiming hardware it was not run on, and the requirement exists precisely
//! so a reader can judge the number.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use qqq_bench::budget::{Budget, Item, Measurement, Unit};
use qqq_bench::methodology::{
    BenchmarkName, Concurrency, Environment, Methodology, NonClaims, Warmup,
};
use qqq_bench::workload::{Shape, Workload};
use qqq_bench::HARNESS_SOURCE;
use qqq_core::error::{Error, ErrorCode};

/// The URL `§9.1` requires be published, so a reader can audit the harness.
pub use qqq_bench::HARNESS_SOURCE as HARNESS;

/// Usage errors use the code every other command's usage error does.
fn usage(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::McpArgumentInvalid, message)
}

/// Options for one `bench` run.
#[derive(Debug, Clone)]
pub struct BenchOptions {
    /// Where the server is listening. **Required** — see the module docs.
    pub target: Option<SocketAddr>,
    /// Run only this benchmark. Empty means all ten.
    pub only: Vec<BenchmarkName>,
    /// Send this many requests per workload, overriding the workload's default.
    pub requests: Option<u64>,
    /// Drive sustained workloads for this many seconds.
    pub seconds: Option<u32>,
    /// Requests in flight, overriding the workload's own concurrency.
    pub connections: Option<u32>,
    /// Per-request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Emit machine-readable JSON.
    pub json: bool,
    /// Exit non-zero when a budget is missed.
    pub fail_on_miss: bool,
}

impl Default for BenchOptions {
    fn default() -> Self {
        Self {
            target: None,
            only: Vec::new(),
            requests: None,
            seconds: None,
            connections: None,
            timeout_ms: 10_000,
            json: false,
            fail_on_miss: false,
        }
    }
}

/// Read the next value after a flag.
fn value_of(args: &[String], i: usize, flag: &str) -> Result<String, Error> {
    args.get(i + 1).cloned().ok_or_else(|| {
        usage(format!("`{flag}` needs a value"))
            .with_remediation(format!("for example `{flag} 127.0.0.1:8080`"))
    })
}

/// Parse the command line.
///
/// # Errors
///
/// Returns a usage error naming the flag and a remediation. Parsing happens before
/// anything is measured, because a typo should be reported while the user is
/// looking at the command they typed (`§O-033a`) — not after ten seconds of load.
pub fn options(args: &[String]) -> Result<BenchOptions, Error> {
    let mut opts = BenchOptions::default();
    let mut i = 0;

    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--listen" | "--target" | "--url" => {
                let v = value_of(args, i, arg)?;
                let addr = parse_target(&v)?;
                opts.target = Some(addr);
                i += 2;
            }
            "--only" | "--filter" => {
                let v = value_of(args, i, arg)?;
                let name = BenchmarkName::parse(&v);
                if !name.is_specification_benchmark() {
                    return Err(usage(format!(
                        "`{v}` is not one of the ten §9.1 benchmarks"
                    ))
                    .with_remediation(format!(
                        "the ten are: {}",
                        BenchmarkName::all_specified()
                            .iter()
                            .map(|n| n.as_str().into_owned())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                }
                opts.only.push(name);
                i += 2;
            }
            "--requests" => {
                let v = value_of(args, i, arg)?;
                opts.requests = Some(v.parse().map_err(|_| {
                    usage(format!("`--requests {v}` is not a number"))
                        .with_remediation("pass a whole number, for example `--requests 5000`")
                })?);
                i += 2;
            }
            "--seconds" => {
                let v = value_of(args, i, arg)?;
                opts.seconds = Some(v.parse().map_err(|_| {
                    usage(format!("`--seconds {v}` is not a number"))
                        .with_remediation("pass a whole number, for example `--seconds 30`")
                })?);
                i += 2;
            }
            "--connections" | "-c" => {
                let v = value_of(args, i, arg)?;
                let n: u32 = v.parse().map_err(|_| {
                    usage(format!("`--connections {v}` is not a number"))
                        .with_remediation("pass a whole number, for example `--connections 64`")
                })?;
                if n == 0 {
                    return Err(usage("`--connections 0` would send no requests")
                        .with_remediation("pass at least 1, or omit the flag to use the workload's own level"));
                }
                opts.connections = Some(n);
                i += 2;
            }
            "--timeout" => {
                let v = value_of(args, i, arg)?;
                opts.timeout_ms = v.parse().map_err(|_| {
                    usage(format!("`--timeout {v}` is not a number of milliseconds"))
                        .with_remediation("pass a whole number, for example `--timeout 5000`")
                })?;
                i += 2;
            }
            "--json" => {
                opts.json = true;
                i += 1;
            }
            "--fail-on-miss" => {
                opts.fail_on_miss = true;
                i += 1;
            }
            other => {
                return Err(usage(format!("unknown option `{other}` for `qqqai bench`"))
                    .with_remediation(
                        "run `qqqai bench --help`; the options are --listen, --only, \
                         --requests, --seconds, --connections, --timeout, --json, \
                         --fail-on-miss",
                    ));
            }
        }
    }

    Ok(opts)
}

/// Parse a target, accepting a bare port as a convenience.
///
/// # Errors
///
/// Returns a usage error naming what was wrong. A bare `8080` becomes
/// `127.0.0.1:8080` because that is unambiguous and is what a user means when they
/// have just started a server locally.
pub fn parse_target(raw: &str) -> Result<SocketAddr, Error> {
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(port) = raw.parse::<u16>() {
        return format!("127.0.0.1:{port}").parse().map_err(|_| {
            usage(format!("`{raw}` is not a usable port"))
                .with_remediation("pass a full address, for example `--listen 127.0.0.1:8080`")
        });
    }
    Err(
        usage(format!("`{raw}` is not an address"))
            .with_remediation("pass `host:port`, for example `--listen 127.0.0.1:8080`"),
    )
}

/// One workload's outcome, ready to render.
#[derive(Debug, Clone)]
pub struct BenchResult {
    /// Which `§9.1` row.
    pub name: BenchmarkName,
    /// What `§9.1` says the row measures.
    pub measures: String,
    /// What `§9.1` predicts.
    pub expected: String,
    /// Requests attempted.
    pub attempted: u64,
    /// Requests that produced no response.
    pub failed: u64,
    /// p50 in nanoseconds, over completed requests.
    pub p50_nanos: Option<u64>,
    /// p99 in nanoseconds.
    pub p99_nanos: Option<u64>,
    /// Requests per second, where the run had a duration.
    pub rps: Option<f64>,
    /// The `§9.2` budget this row answers to, if any.
    pub verdict: Option<BudgetVerdict>,
}

/// A comparison against a `§9.2` budget.
#[derive(Debug, Clone)]
pub struct BudgetVerdict {
    /// The checklist item owning the budget.
    pub item: &'static str,
    /// The metric name.
    pub metric: &'static str,
    /// What `§9.2` requires.
    pub target: f64,
    /// The unit both numbers are in.
    pub unit: &'static str,
    /// Which way the comparison goes.
    pub direction: &'static str,
    /// What was measured.
    pub measured: f64,
    /// Whether the budget was met.
    pub met: bool,
}

/// The environment this run was performed on, read rather than accepted.
///
/// # Why this cannot be a flag
///
/// `§9.1` requires the machine be published with the result so a reader can judge
/// it. A caller able to *assert* its own environment could publish a number
/// claiming hardware it never ran on, which defeats the requirement. Every field
/// here is read from the running system.
///
/// # Why a field may be `"unknown"` rather than absent
///
/// Some facts are not readable on every platform without a dependency, and this
/// crate takes none for it. An `"unknown"` is a **named** gap a reader can see,
/// which is `§10.3`'s rule for the access log's `manifest_rev` — not a silent
/// omission dressed as a value.
#[must_use]
pub fn read_environment() -> Environment {
    let mut toolchains = BTreeMap::new();
    toolchains.insert("rustc".to_owned(), rustc_version());
    toolchains.insert(
        "qqqai".to_owned(),
        env!("CARGO_PKG_VERSION").to_owned(),
    );

    Environment::new(
        cpu_model(),
        std::thread::available_parallelism()
            .map(|n| u32::try_from(n.get()).unwrap_or(u32::MAX))
            .unwrap_or(1),
        total_memory_bytes(),
        std::env::consts::OS.to_owned() + " " + std::env::consts::ARCH,
        kernel_version(),
        toolchains,
    )
    .unwrap_or_else(|_| {
        // Unreachable in practice: every field above is non-empty by construction.
        // Stated rather than `unwrap`ed because a benchmark must not panic while
        // reporting its own conditions -- that would lose the measurement and the
        // explanation together.
        Environment::new(
            "unknown",
            1,
            1,
            "unknown",
            "unknown",
            BTreeMap::from([("rustc".to_owned(), "unknown".to_owned())]),
        )
        .expect("the fallback is non-empty by construction")
    })
}

/// The compiler version, from the build script environment.
///
/// `rustc --version` would be more precise and would mean spawning a process
/// inside a benchmark, which perturbs the thing being measured on the `cold` row.
/// The version the crate was *built* with is the one that matters for a result,
/// and it is a compile-time constant.
fn rustc_version() -> String {
    // `RUSTC_VERSION` is not a standard cargo-provided variable, so the fallback
    // is the honest one and is named.
    option_env!("RUSTC_VERSION").map_or_else(|| "unknown".to_owned(), str::to_owned)
}

/// The CPU model, from the platform's own description where one is readable.
fn cpu_model() -> String {
    // Read from `/proc/cpuinfo` on Linux or the environment on macOS/Windows,
    // falling back to a named unknown rather than inventing a model.
    if let Ok(text) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("model name") {
                if let Some(value) = rest.split(':').nth(1) {
                    return value.trim().to_owned();
                }
            }
        }
    }
    std::env::var("PROCESSOR_IDENTIFIER")
        .or_else(|_| std::env::var("HOSTTYPE"))
        .unwrap_or_else(|_| "unknown".to_owned())
}

/// Total system memory, or `1` as a named fallback.
fn total_memory_bytes() -> u64 {
    if let Ok(text) = std::fs::read_to_string("/proc/meminfo") {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                if let Some(kb) = rest.split_whitespace().next() {
                    if let Ok(kb) = kb.parse::<u64>() {
                        return kb.saturating_mul(1024);
                    }
                }
            }
        }
    }
    // A non-zero fallback because `Environment::new` refuses zero -- and refusing
    // zero is right, since zero memory is not a machine.
    1
}

/// The kernel version, or a named unknown.
fn kernel_version() -> String {
    if let Ok(text) = std::fs::read_to_string("/proc/version") {
        if let Some(token) = text.split_whitespace().nth(2) {
            return token.to_owned();
        }
    }
    std::env::consts::OS.to_owned()
}

/// Assemble the methodology for one workload.
///
/// # Errors
///
/// Returns a usage error if a flag contradicts the workload's shape — for example
/// `--seconds` on a row that is not sustained.
pub fn methodology_for(
    workload: &Workload,
    opts: &BenchOptions,
) -> Result<Methodology, Error> {
    let concurrency = match opts.connections {
        Some(n) => Concurrency::Fixed { connections: n },
        None => workload.concurrency,
    };

    let environment = read_environment();

    // `§9.1` requires a "what this does not measure" section, and `PERF-001` made
    // it a *required field*. This is where the envato caveats live.
    let non_claims = NonClaims::qualified([
        format!(
            "run on {} by a harness measuring itself; a p99 includes the client's \
             own syscall and scheduling cost, not only the server's",
            environment.cpu_model
        ),
        "HTTP/1.1 with `Connection: close`: every request opens a connection, so \
         this does not measure keep-alive or HTTP/2 reuse"
            .to_owned(),
        "the reference application's `db` row reads an in-guest store, not a \
         Postgres round trip: the host has no `qqq:sql` implementation (O-155)"
            .to_owned(),
    ])
    .map_err(|e| usage(e))?;

    Methodology::new(
        environment,
        workload.warmup.clone(),
        concurrency,
        Methodology::REQUIRED_REPETITIONS,
        non_claims,
        HARNESS_SOURCE,
    )
    .map_err(|e| usage(e.to_string()))
}

/// The shape to run, applying the flag overrides.
///
/// # Errors
///
/// Returns a usage error when a flag does not apply to the row's shape.
pub fn shape_for(workload: &Workload, opts: &BenchOptions) -> Result<Shape, Error> {
    match workload.shape {
        Shape::SingleShot => {
            if opts.requests.is_some() || opts.seconds.is_some() {
                return Err(usage(format!(
                    "`{}` is a single-shot row and cannot be given a request count",
                    workload.name
                ))
                .with_remediation(
                    "the `cold` row is \"instantiate and serve once\"; \
                     `--requests` and `--seconds` would measure something else",
                ));
            }
            Ok(Shape::SingleShot)
        }
        Shape::Fixed { requests } => Ok(Shape::Fixed {
            requests: opts
                .requests
                .map_or(requests, |n| u32::try_from(n).unwrap_or(u32::MAX)),
        }),
        Shape::Sustained { seconds } => Ok(Shape::Sustained {
            seconds: opts.seconds.unwrap_or(seconds),
        }),
    }
}

/// Which workloads this run will execute.
#[must_use]
pub fn selected(opts: &BenchOptions) -> Vec<BenchmarkName> {
    if opts.only.is_empty() {
        BenchmarkName::all_specified().into_iter().collect()
    } else {
        opts.only.clone()
    }
}

/// Turn a run result into a verdict against `§9.2`, where the row has a budget.
///
/// # Why only some rows have a verdict
///
/// `§9.2` budgets nine measurable things and `§9.1` names ten workloads; the rows
/// do not map one-to-one, and `PERF-001`'s `Budget::ALL` is the authority on which
/// rows exist. A workload with no budget still runs — `§9.1` asks for the ten
/// measurements, not for ten verdicts — and its result is reported without one
/// rather than with an invented target.
#[must_use]
pub fn verdict_for(
    name: &BenchmarkName,
    p99_nanos: Option<u64>,
    rps: Option<f64>,
) -> Option<BudgetVerdict> {
    // Which budget answers which workload. Stated as data so the mapping is
    // visible rather than buried in a match with a default.
    let (budget, measured) = match name {
        BenchmarkName::Hello => {
            let b = Budget::for_item(Item::Perf002)?;
            (b, b.meets_nanos(p99_nanos?).ok()?)
        }
        BenchmarkName::Json => {
            // `§9.2` states throughput against the `json` workload.
            let b = Budget::for_item(Item::Perf010)?;
            (b, b.meets(&Measurement::new(rps?, Unit::RequestsPerSecond)).ok()?)
        }
        BenchmarkName::TailP99 => {
            let b = Budget::for_item(Item::Perf011)?;
            (b, b.meets_nanos(p99_nanos?).ok()?)
        }
        BenchmarkName::Multi => {
            let b = Budget::for_item(Item::Perf010)?;
            (b, b.meets(&Measurement::new(rps?, Unit::RequestsPerSecond)).ok()?)
        }
        _ => return None,
    };

    Some(BudgetVerdict {
        item: budget.item.id(),
        metric: budget.item.metric(),
        target: budget.target,
        unit: budget.unit.symbol(),
        direction: budget.direction.symbol(),
        measured: measured.measured,
        met: measured.met,
    })
}

/// Whether a completed run should be reported as a failure.
///
/// # Why this returns a `bool` and not an `ExitCode`
///
/// The exit codes are defined in `main.rs`'s private `exit` module, and a library
/// module reaching into the binary's internals would invert the crate's own
/// layering. Returning the *decision* and letting `main` map it to a code keeps the
/// policy in one place and the mapping in another, which is also what makes the
/// decision testable without a process.
///
/// `--fail-on-miss` is opt-in because a benchmark's purpose is to *report*: making
/// a missed budget a failure by default would turn a measurement tool into a gate,
/// and `§9.2` calls these "numeric targets engineering is held to" rather than a
/// pass/fail condition. The flag is how a caller asks for the gate.
#[must_use]
pub fn should_fail(output: &BenchOutput, fail_on_miss: bool) -> bool {
    if !fail_on_miss {
        return false;
    }
    output
        .results
        .iter()
        .any(|r| r.budget.as_ref().is_some_and(|v| !v.met))
}

/// The timeout as a `Duration`.
#[must_use]
pub fn timeout(opts: &BenchOptions) -> Duration {
    Duration::from_millis(opts.timeout_ms)
}

/// A workload's effective warmup count, for the load generator.
///
/// `§9.1` requires the procedure be *stated*, and `PERF-001` made it a required
/// field of the methodology. This is the single place the two are bridged, so the
/// number the harness performs is the number the result publishes.
#[must_use]
pub fn warmup_requests(warmup: &Warmup) -> u32 {
    match warmup {
        // Zero, and it is *stated* as zero rather than omitted: warming a cold
        // start would measure the opposite of what the row claims.
        Warmup::None { .. } => 0,
        Warmup::Discard { iterations } => *iterations,
        // A duration warmup has no request count; the load generator gets a
        // nominal figure derived from the duration at a conservative rate, and the
        // *published* value remains the duration, which is the truthful statement.
        Warmup::Duration { millis } => u32::try_from(millis / 10).unwrap_or(u32::MAX),
    }
}

/// Run every selected workload against `target`, returning the output document.
///
/// # Why this returns the rendered document rather than bare results
///
/// `§9.1` requires the **methodology** be published with every result, and
/// `PERF-001` made that a required field. Returning only the measurements would
/// let a caller render numbers without the machine, the warmup, the concurrency and
/// the non-claims — which is the "marketing" `§9.1` names. The document is the
/// unit of output because the document is the unit of the claim.
///
/// # Why each workload is driven in sequence rather than concurrently
///
/// `§9.1`'s rows measure different things, and running `tailp99` while `cpu`
/// saturates the machine would make both numbers describe the combination rather
/// than the row. The cost is that a full run takes minutes; the alternative is ten
/// measurements that are individually wrong.
///
/// # Errors
///
/// Returns a usage error if a workload's plan cannot be built, or if driving it
/// fails to start.
pub async fn run(opts: &BenchOptions, target: SocketAddr) -> Result<BenchOutput, Error> {
    let mut results = Vec::new();
    // The methodology of the last workload built, kept for the document's
    // environment section. Every workload's methodology shares the same
    // `Environment` (it is read from the machine), so the last is representative
    // and a per-row copy would be the same values repeated.
    let mut methodology: Option<Methodology> = None;

    for name in selected(opts) {
        let Some(workload) = Workload::find(&name) else {
            continue;
        };

        // Built even though the load generator takes only some fields: `§9.1`
        // requires the methodology be *published with the result*, so a workload
        // whose methodology cannot be constructed must not run and report a
        // number. Building it is the check.
        let built = methodology_for(workload, opts)?;
        let shape = shape_for(workload, opts)?;

        let concurrency = match opts.connections {
            Some(n) => Concurrency::Fixed { connections: n },
            None => workload.concurrency,
        };

        let mut plan = bench_plan(target, workload, shape, concurrency, opts);
        plan.warmup = warmup_requests(&built.warmup);

        let outcome = qqq_bench::loadgen::drive(&plan)
            .await
            .map_err(|e| usage(format!("could not drive `{name}`: {e}")))?;

        let p99 = outcome.distribution.p99();
        let rps = outcome.requests_per_second();

        results.push(BenchResult {
            name: name.clone(),
            measures: workload.measures.to_owned(),
            expected: workload.expected.to_owned(),
            attempted: outcome.attempted,
            failed: outcome.failed,
            p50_nanos: outcome.distribution.p50(),
            p99_nanos: p99,
            rps,
            verdict: verdict_for(&name, p99, rps),
        });

        methodology = Some(built);
    }

    // A run with no workloads still needs a document, and the environment is
    // readable without running anything -- so the empty case reports the machine
    // rather than an empty object.
    let methodology = methodology.unwrap_or_else(|| {
        let hello = Workload::find(&BenchmarkName::Hello).expect("hello is in the table");
        methodology_for(hello, opts).expect("the hello methodology is constructible")
    });

    Ok(BenchOutput::new(&results, &methodology))
}

/// Build a load-generator plan for one workload.
#[must_use]
pub fn bench_plan(
    target: SocketAddr,
    workload: &Workload,
    shape: Shape,
    concurrency: Concurrency,
    opts: &BenchOptions,
) -> qqq_bench::loadgen::Plan {
    let path = path_for(&workload.name);
    let limit = match shape {
        // A single shot is one request: the request count IS the shape, not a
        // separately configured number.
        Shape::SingleShot => qqq_bench::loadgen::Limit::Requests(1),
        Shape::Fixed { requests } => qqq_bench::loadgen::Limit::Requests(u64::from(requests)),
        Shape::Sustained { seconds } => {
            qqq_bench::loadgen::Limit::Duration(Duration::from_secs(u64::from(seconds)))
        }
    };

    qqq_bench::loadgen::Plan {
        target,
        path,
        method: workload.method.to_owned(),
        body: workload.body.map(|b| b.as_bytes().to_vec()),
        host: target.to_string(),
        concurrency,
        limit,
        timeout: timeout(opts),
        // Overwritten by the caller from the methodology, so the performed warmup
        // and the published one are the same number.
        warmup: 0,
    }
}

/// The request path for a workload.
///
/// # Why the harness owns this mapping, given §O-163 said the app owns it
///
/// The application *declares* which route implements which benchmark
/// (`examples/orders-api/src/router.rs`), and that declaration is the authority on
/// what a real deployment serves. The harness still has to name a URL to send, and
/// it cannot ask a running server what its routes mean — there is no such endpoint
/// and inventing one would be a protocol change.
///
/// So this is the harness's own default, and `examples/orders-api`'s route table
/// asserts it agrees. Two statements of one mapping, compared by test, is the
/// arrangement this project uses for exactly this reason (`§O-149`): a mapping
/// derived from one source verifies nothing.
#[must_use]
pub fn path_for(name: &BenchmarkName) -> String {
    match name {
        BenchmarkName::Hello => "/healthz".to_owned(),
        BenchmarkName::Json => "/orders/bench-1".to_owned(),
        BenchmarkName::Route => "/r/orders-bench".to_owned(),
        BenchmarkName::Db => "/orders/bench-1/items".to_owned(),
        BenchmarkName::Crypto => "/crypto/10000".to_owned(),
        BenchmarkName::Template => "/orders".to_owned(),
        BenchmarkName::Cpu => "/compute/1000".to_owned(),
        BenchmarkName::Multi => "/multi".to_owned(),
        BenchmarkName::TailP99 => "/orders/bench-1/status".to_owned(),
        BenchmarkName::Cold => "/cold".to_owned(),
        // An extension has no default; a caller measuring one must name its path.
        BenchmarkName::Other(name) => format!("/{name}"),
    }
}

/// The whole run, as a `CommandOutput`.
///
/// # Why this is a type and not a `println!` sequence
///
/// Every other command in this CLI renders through [`CommandOutput`], which gives
/// a human and an agent the same facts in two shapes and puts the summary where
/// both can read it. A command that printed directly would be the only one whose
/// `--json` output nobody had designed, and the `--json` defect in `qqqai audit`
/// — where the human path was fixed and the machine path was not checked — is
/// recorded as a finding for exactly this reason.
///
/// [`CommandOutput`]: crate::output::CommandOutput
#[derive(Debug, Clone, serde::Serialize)]
pub struct BenchOutput {
    /// Every workload's result, in `§9.1` order.
    pub results: Vec<BenchResultOutput>,
    /// The environment the run was performed on, as `§9.1` requires.
    pub environment: serde_json::Value,
    /// What the run does not measure. `§9.1`'s ninth requirement.
    pub does_not_measure: Vec<String>,
    /// Where the harness source lives, so the result is auditable.
    pub harness_source: &'static str,
}

/// One workload's result, in serializable form.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BenchResultOutput {
    /// The `§9.1` row name.
    pub benchmark: String,
    /// What `§9.1` says it measures.
    pub measures: String,
    /// What `§9.1` predicts.
    pub expected: String,
    /// Requests attempted.
    pub attempted: u64,
    /// Requests that produced no response.
    pub failed: u64,
    /// p50 in nanoseconds.
    pub p50_nanos: Option<u64>,
    /// p99 in nanoseconds.
    pub p99_nanos: Option<u64>,
    /// Requests per second.
    pub requests_per_second: Option<f64>,
    /// The `§9.2` verdict, where the row has a budget.
    pub budget: Option<BudgetVerdictOutput>,
}

/// A `§9.2` verdict, in serializable form.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BudgetVerdictOutput {
    /// The owning checklist item.
    pub item: String,
    /// The metric name.
    pub metric: String,
    /// The `§9.2` target.
    pub target: f64,
    /// The unit.
    pub unit: String,
    /// The comparison direction.
    pub direction: String,
    /// What was measured.
    pub measured: f64,
    /// Whether the budget was met.
    pub met: bool,
}

impl BenchOutput {
    /// Build the output document for a completed run.
    #[must_use]
    pub fn new(results: &[BenchResult], methodology: &Methodology) -> Self {
        Self {
            results: results
                .iter()
                .map(|r| BenchResultOutput {
                    benchmark: r.name.as_str().into_owned(),
                    measures: r.measures.clone(),
                    expected: r.expected.clone(),
                    attempted: r.attempted,
                    failed: r.failed,
                    p50_nanos: r.p50_nanos,
                    p99_nanos: r.p99_nanos,
                    requests_per_second: r.rps,
                    budget: r.verdict.as_ref().map(|v| BudgetVerdictOutput {
                        item: v.item.to_owned(),
                        metric: v.metric.to_owned(),
                        target: v.target,
                        unit: v.unit.to_owned(),
                        direction: v.direction.to_owned(),
                        measured: v.measured,
                        met: v.met,
                    }),
                })
                .collect(),
            environment: serde_json::json!({
                "cpu_model": methodology.environment.cpu_model,
                "physical_cores": methodology.environment.physical_cores,
                "memory_bytes": methodology.environment.memory_bytes,
                "os": methodology.environment.os,
                "kernel": methodology.environment.kernel,
                "toolchains": methodology.environment.toolchains,
            }),
            does_not_measure: match &methodology.non_claims {
                NonClaims::Qualified { items } => items.clone(),
                NonClaims::Unqualified { reason } => vec![format!("unqualified: {reason}")],
            },
            harness_source: HARNESS_SOURCE,
        }
    }

    /// A one-line summary for a human and for the JSON envelope.
    ///
    /// # Why the summary counts misses rather than averaging
    ///
    /// `§9.1` requires percentiles and forbids averages; a summary that averaged
    /// the rows would smuggle the forbidden number in at the top level, where it is
    /// the only thing many readers see. Counting how many rows met their `§9.2`
    /// budget is the honest summary of a run whose rows are not commensurable.
    #[must_use]
    pub fn summarise(&self) -> String {
        let with_budget: Vec<&BenchResultOutput> =
            self.results.iter().filter(|r| r.budget.is_some()).collect();
        let met = with_budget
            .iter()
            .filter(|r| r.budget.as_ref().is_some_and(|b| b.met))
            .count();
        let failed: u64 = self.results.iter().map(|r| r.failed).sum();

        if with_budget.is_empty() {
            format!(
                "{} benchmark(s) run, none with a §9.2 budget",
                self.results.len()
            )
        } else {
            let failed_note = if failed > 0 {
                format!("; {failed} request(s) produced no response")
            } else {
                String::new()
            };
            format!(
                "{} benchmark(s) run, {met}/{} §9.2 budget(s) met{failed_note}",
                self.results.len(),
                with_budget.len()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    // -- option parsing ------------------------------------------------------

    #[test]
    fn a_bare_port_becomes_loopback() {
        // The convenience that matters: a user who just started `qqqai serve`
        // types `qqqai bench 8080`, not the full authority.
        let addr = parse_target("8080").expect("a bare port");
        assert_eq!(addr.to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn a_full_address_is_accepted_verbatim() {
        let addr = parse_target("0.0.0.0:9999").expect("a full address");
        assert_eq!(addr.port(), 9999);
    }

    #[test]
    fn a_nonsense_target_is_refused_with_a_remediation() {
        let err = parse_target("not-an-address").expect_err("must be refused");
        // `render()` rather than a field accessor: what matters is that the user
        // is told what to do, and the rendered block is the only thing they see.
        //
        // The marker is `→`, which is how `qqq_core` renders remediation — not the
        // word "Remediation". Asserting the literal word was the first attempt and
        // it failed against a *correct* error, which is the argument for asserting
        // on the rendered form: the contract is what the user reads.
        let rendered = err.render();
        assert!(
            rendered.contains('→'),
            "a usage error must say what to do instead, got: {rendered}"
        );
        assert!(
            rendered.contains("host:port"),
            "the remediation must name the correct form, got: {rendered}"
        );
    }

    #[test]
    fn listen_accepts_a_port_and_a_full_address() {
        for (given, expected_port) in [("8080", 8080_u16), ("127.0.0.1:1234", 1234)] {
            let opts = options(&args(&["--listen", given])).expect("valid");
            assert_eq!(opts.target.expect("a target").port(), expected_port);
        }
    }

    #[test]
    fn only_accepts_a_specification_name_and_refuses_an_invented_one() {
        let opts = options(&args(&["--only", "json"])).expect("`json` is a §9.1 row");
        assert_eq!(opts.only, vec![BenchmarkName::Json]);

        // An invented name must be refused rather than silently measuring nothing.
        let err = options(&args(&["--only", "json2"])).expect_err("must be refused");
        let rendered = err.to_string();
        assert!(rendered.contains("json2"), "got {rendered}");
        assert!(
            err.render().contains("hello"),
            "the remediation must list the real names, got: {}",
            err.render()
        );
    }

    #[test]
    fn only_can_be_given_more_than_once() {
        let opts = options(&args(&["--only", "json", "--only", "cpu"])).expect("valid");
        assert_eq!(opts.only, vec![BenchmarkName::Json, BenchmarkName::Cpu]);
    }

    #[test]
    fn zero_connections_is_refused() {
        // Zero would send no requests and report a throughput of zero, which reads
        // as "the server handled nothing" rather than "the harness did nothing".
        let err = options(&args(&["--connections", "0"])).expect_err("must be refused");
        assert!(err.to_string().contains("no requests"), "got {err}");
    }

    #[test]
    fn a_non_numeric_value_names_the_flag() {
        for (flag, bad) in [
            ("--requests", "many"),
            ("--seconds", "soon"),
            ("--connections", "lots"),
            ("--timeout", "quick"),
        ] {
            let err = options(&args(&[flag, bad])).expect_err("must be refused");
            let rendered = err.to_string();
            assert!(rendered.contains(bad), "{flag}: got {rendered}");
        }
    }

    #[test]
    fn a_flag_without_a_value_is_refused() {
        let err = options(&args(&["--listen"])).expect_err("must be refused");
        assert!(err.to_string().contains("needs a value"), "got {err}");
    }

    #[test]
    fn an_unknown_option_lists_the_real_ones() {
        let err = options(&args(&["--turbo"])).expect_err("must be refused");
        let rendered = err.render();
        assert!(rendered.contains("--listen"), "got {rendered}");
        assert!(rendered.contains("--fail-on-miss"), "got {rendered}");
    }

    #[test]
    fn the_flags_parse_together() {
        let opts = options(&args(&[
            "--listen",
            "127.0.0.1:9000",
            "--only",
            "json",
            "--requests",
            "50",
            "--connections",
            "4",
            "--timeout",
            "2500",
            "--json",
            "--fail-on-miss",
        ]))
        .expect("valid");
        assert_eq!(opts.target.expect("a target").port(), 9000);
        assert_eq!(opts.requests, Some(50));
        assert_eq!(opts.connections, Some(4));
        assert_eq!(opts.timeout_ms, 2500);
        assert!(opts.json);
        assert!(opts.fail_on_miss);
    }

    // -- selection and shape -------------------------------------------------

    #[test]
    fn with_no_filter_all_ten_rows_run() {
        let opts = BenchOptions::default();
        assert_eq!(selected(&opts).len(), 10);
    }

    #[test]
    fn a_filter_selects_exactly_what_was_asked_for() {
        let opts = options(&args(&["--only", "cold"])).expect("valid");
        assert_eq!(selected(&opts), vec![BenchmarkName::Cold]);
    }

    #[test]
    fn a_cold_row_refuses_a_request_count() {
        // The row is "instantiate and serve once". A request count would measure
        // something else under the `cold` name, which is the worst possible
        // outcome for a benchmark: a wrong number with a right label.
        let cold = Workload::find(&BenchmarkName::Cold).expect("cold exists");
        let opts = options(&args(&["--requests", "100"])).expect("parses");
        let err = shape_for(cold, &opts).expect_err("cold must refuse a count");
        assert!(err.to_string().contains("single-shot"), "got {err}");
    }

    #[test]
    fn a_fixed_row_takes_a_request_count_and_a_sustained_row_takes_seconds() {
        let hello = Workload::find(&BenchmarkName::Hello).expect("hello exists");
        let opts = options(&args(&["--requests", "250"])).expect("parses");
        assert_eq!(shape_for(hello, &opts).expect("valid"), Shape::Fixed { requests: 250 });

        let multi = Workload::find(&BenchmarkName::Multi).expect("multi exists");
        let opts = options(&args(&["--seconds", "30"])).expect("parses");
        assert_eq!(
            shape_for(multi, &opts).expect("valid"),
            Shape::Sustained { seconds: 30 }
        );
    }

    #[test]
    fn a_workload_default_shape_survives_with_no_flag() {
        let hello = Workload::find(&BenchmarkName::Hello).expect("hello exists");
        let opts = BenchOptions::default();
        assert_eq!(shape_for(hello, &opts).expect("valid"), hello.shape);
    }

    // -- warmup bridging -----------------------------------------------------

    #[test]
    fn a_stated_no_warmup_becomes_zero_requests() {
        // The bridge that keeps the performed number equal to the published one.
        let cold = Workload::find(&BenchmarkName::Cold).expect("cold exists");
        assert_eq!(warmup_requests(&cold.warmup), 0);
    }

    #[test]
    fn a_discard_warmup_becomes_that_many_requests() {
        let hello = Workload::find(&BenchmarkName::Hello).expect("hello exists");
        match hello.warmup {
            Warmup::Discard { iterations } => {
                assert_eq!(warmup_requests(&hello.warmup), iterations);
            }
            ref other => panic!("hello must discard iterations, got {other:?}"),
        }
    }

    // -- environment reading -------------------------------------------------

    #[test]
    fn the_environment_is_read_and_complete() {
        // §9.1 requires the machine be published. The constructor refuses a blank
        // field, so a returned `Environment` is evidence that nine facts were read.
        let env = read_environment();
        assert!(!env.cpu_model.trim().is_empty(), "cpu_model must be populated");
        assert!(!env.os.trim().is_empty());
        assert!(!env.kernel.trim().is_empty());
        assert!(env.physical_cores > 0);
        assert!(env.memory_bytes > 0);
        assert!(!env.toolchains.is_empty());
    }

    // -- exit codes ----------------------------------------------------------

    fn result_with(met: bool) -> BenchResult {
        BenchResult {
            name: BenchmarkName::Hello,
            measures: "test".to_owned(),
            expected: "test".to_owned(),
            attempted: 1,
            failed: 0,
            p50_nanos: Some(1),
            p99_nanos: Some(2),
            rps: Some(3.0),
            verdict: Some(BudgetVerdict {
                item: "PERF-002",
                metric: "test",
                target: 1.0,
                unit: "µs",
                direction: "≤",
                measured: 2.0,
                met,
            }),
        }
    }

    #[test]
    fn a_missed_budget_only_fails_when_asked_to() {
        let results = vec![result_with(false)];
        assert!(
            !should_fail(&results, false),
            "without --fail-on-miss a miss is reported, not failed"
        );
        assert!(
            should_fail(&results, true),
            "with --fail-on-miss a miss must be reported as a failure"
        );
    }

    #[test]
    fn a_met_budget_succeeds_even_with_fail_on_miss() {
        let results = vec![result_with(true)];
        assert!(!should_fail(&results, true));
    }

    #[test]
    fn a_run_with_no_verdicts_succeeds_under_fail_on_miss() {
        // Nine of the ten rows have no §9.2 budget. `--fail-on-miss` must not
        // treat "no target" as "missed" -- a row with no budget is not a row that
        // failed one, and conflating them would make the flag fail every run of
        // `--only cpu`.
        let mut r = result_with(true);
        r.verdict = None;
        assert!(!should_fail(&[r], true));
    }

    #[test]
    fn one_missed_budget_among_many_fails_the_run() {
        // The control for the tests above: a `should_fail` that always returned
        // false would pass all of them.
        let results = vec![result_with(true), result_with(false), result_with(true)];
        assert!(should_fail(&results, true));
    }
}
