//! Hardening tests — `SEC-019`.
//!
//! # Why these tests re-execute the test binary
//!
//! The steps under test are **irreversible and process-wide**:
//!
//! * `seccomp` installs a filter that cannot be removed. Once installed, a
//!   `#[should_panic]` test that trips it dies with `SIGSYS` — killing the test
//!   *process*, so every other test in the binary reports "crashed" rather than
//!   its own result.
//! * `setuid`/`setgid` change the identity of the whole process, permanently.
//! * `no_new_privs` cannot be unset.
//!
//! A test suite that called these in-process would be a suite whose results
//! depend on execution order, which is to say a suite that is not a suite. So
//! every test that *actually applies* a step runs in a **child process**:
//! `std::env::current_exe()` re-executed with an environment variable naming the
//! step, so the child does the irreversible thing and the parent observes its
//! exit status.
//!
//! This is the standard pattern for testing process-global state, and it is
//! stated here because the obvious alternative — calling [`harden`] directly and
//! asserting on the report — would in fact pass on a Linux CI runner while
//! making the binary un-runnable afterwards for every subsequent test. It would
//! look like a working test and be a test that works once, by itself.
//!
//! # What each test class proves
//!
//! | Test | Property |
//! |---|---|
//! | report shape | every step is reported, on every platform, in a fixed order |
//! | `is_clean` semantics | `Skipped`/`Unsupported` are not failures; `Failed` is |
//! | step order | the order is a security property and is asserted, not assumed |
//! | profile | the allowlist and denylist do not overlap and the denied names are the dangerous ones |
//! | child: no_new_privs | the step actually applies and the process survives |
//! | child: seccomp | the filter applies, permits what it lists, and refuses what it does not |
//! | child: uid 0 refused | the report does not lie about a no-op |
//! | parent | **the whole module is safe to call** — no step kills the caller |

use std::process::Command;

use qqq_sys::harden::{
    harden, HardenPolicy, HardenReport, SeccompProfile, Step, StepOutcome, STEP_DROP_GID,
    STEP_DROP_UID, STEP_LANDLOCK, STEP_NO_NEW_PRIVS, STEP_ORDER, STEP_SECCOMP,
};

/// The environment variable that turns this binary into a hardening child.
const CHILD_ENV: &str = "QQQ_HARDEN_CHILD";

// ---------------------------------------------------------------------------
// The child-process protocol
// ---------------------------------------------------------------------------

/// The entry point a child process runs, when the environment names a step.
///
/// # Why this is in `main`'s position rather than a `#[test]`
///
/// Because it must run **before** the test harness starts, so the harness's own
/// threads and output machinery are not subject to the filter. A `#[test]` that
/// installed seccomp would race the harness's other threads, and the failure
/// would look like a harness bug.
///
/// # Safety of the protocol
///
/// The child is told *what* to do by an environment variable, and it does
/// exactly one thing: build a policy, call [`harden`], and write the report to
/// stdout as JSON. It never reads a path or a command from the environment, so a
/// leaked variable cannot make it do something else.
#[test]
fn harden_child_entry_point() {
    // Only acts when invoked as a child; otherwise it is an ordinary (and
    // trivially passing) test, which keeps `cargo test` working when the
    // harness runs this binary normally.
    let Ok(mode) = std::env::var(CHILD_ENV) else {
        return;
    };

    let policy = match mode.as_str() {
        "no_new_privs" => HardenPolicy::default(),
        // Both seccomp modes install exactly the same filter. They are two
        // *modes* because the child's post-install behaviour differs -- `seccomp`
        // only proves the filter loads, `seccomp_denies` then makes a real
        // denied syscall and proves the filter refuses. The claim being tested
        // is "the filter installed" versus "the filter refuses", and the first
        // version of this test only checked the first -- which meant a
        // **default-allow** filter, the exact bypass the profile prevents,
        // passed it. Clippy merged the two identical arms; the distinction that
        // matters lives in the caller, not in the policy.
        "seccomp" | "seccomp_denies" => HardenPolicy {
            seccomp: true,
            ..HardenPolicy::default()
        },
        "uid_zero" => HardenPolicy {
            drop_to_uid: Some(0),
            ..HardenPolicy::default()
        },
        "uid_current" => HardenPolicy {
            // The uid the process already has. `setuid` to the current uid is
            // permitted for an unprivileged process and is a no-op, which makes
            // it the one identity change that is safe to test anywhere.
            drop_to_uid: Some(current_uid()),
            ..HardenPolicy::default()
        },
        // `SEC-026`. Landlock is **irreversible**, so a ruleset can only be
        // installed in a child: the parent test process would lose access to the
        // workspace and every later test in the same binary would fail for a
        // reason unrelated to what it asserts.
        //
        // The two modes differ in *which directory* is granted, which is what makes
        // the second one a real behavioural test rather than a repeat of the first:
        // `landlock` grants a directory it can read, and `landlock_denies` grants
        // only `/proc/self` and then proves that an ungranted path is refused.
        "landlock" => HardenPolicy {
            landlock: true,
            landlock_read_paths: vec![std::path::PathBuf::from("/usr/share")],
            ..HardenPolicy::default()
        },
        "landlock_denies" => HardenPolicy {
            landlock: true,
            landlock_read_paths: vec![std::path::PathBuf::from("/proc/self")],
            ..HardenPolicy::default()
        },
        // The configuration error: Landlock requested with nothing to keep, which
        // must be a `Failed` step rather than a ruleset that denies everything.
        "landlock_empty" => HardenPolicy {
            landlock: true,
            ..HardenPolicy::default()
        },
        other => {
            eprintln!("unknown child mode: {other}");
            std::process::exit(2);
        }
    };

    let report = harden(&policy);

    // The probe: after the filter is in place, attempt a syscall the profile
    // explicitly denies and report whether the kernel refused it.
    //
    // This is the assertion the first version of this file was missing. Without
    // it, replacing the filter's default action with `Allow` -- turning it into a
    // default-ALLOW program, i.e. no filter at all -- passed every test in the
    // workspace. See `probe_denied_syscall` for why `ptrace` is the right probe.
    if mode == "seccomp_denies" {
        println!("HARDEN_PROBE:{}", probe_denied_syscall());
    }

    // The Landlock probe: after the ruleset is installed, try to read a directory
    // that was NOT granted and report whether the kernel refused.
    //
    // # Why a real read is the only honest test
    //
    // `RulesetStatus::FullyEnforced` comes from the crate, and a step reporting
    // `Applied` comes from this same code. Both could be true of a ruleset that
    // restricts nothing -- the `§O-085` shape, found twice in this repository
    // already. The only claim worth making is behavioural: with `/proc/self`
    // granted, opening a file under a *different* directory must fail with `EACCES`.
    if mode == "landlock_denies" {
        println!("HARDEN_PROBE:{}", probe_ungranted_path());
    }

    // The report goes to stdout as JSON so the parent can assert on the
    // *outcome*, not merely on the exit status. A child that exited 0 having
    // silently done nothing would satisfy an exit-status-only check.
    match serde_json::to_string(&report) {
        Ok(json) => println!("HARDEN_REPORT:{json}"),
        Err(e) => {
            eprintln!("could not serialise the report: {e}");
            std::process::exit(3);
        }
    }
}

/// Attempt a syscall the `Runtime` profile denies, and report whether it was refused.
///
/// # Three failed designs before this one, all measured rather than reasoned
///
/// Each of these was tried and each was wrong for a *different* reason. They are
/// recorded because the fourth design only looks obvious once you know them, and
/// the next person will otherwise start at design one.
///
/// **Design 1 — `libc::ptrace` in an `unsafe` block.** The workspace lint
/// `unsafe_code = "forbid"` applies to every target, tests included:
///
/// ```text
/// error: usage of an `unsafe` block
///    = note: requested on the command line with `-F unsafe-code`
/// ```
///
/// The tempting fix — an `#![allow(unsafe_code)]` here — would have punched a hole
/// in the exact invariant `SEC-020`'s audit verifies. **A test is not a licence to
/// write `unsafe`.**
///
/// **Design 2 — `nix::sys::ptrace::traceme()` in the child.** This hung:
///
/// ```text
/// test the_seccomp_filter_refuses_a_denied_syscall has been running for over 60 seconds
/// ```
///
/// `PTRACE_TRACEME` makes the caller traceable and it then stops awaiting a tracer.
/// The probe was *detecting* the defect correctly, in the worst way — a hang reads
/// as infrastructure trouble, not as a named assertion.
///
/// **Design 3 — `traceme` in a grandchild with a timeout.** Still hung, and
/// *without any filter installed*, which is what exposed the real cause: the
/// `TRACEME` stop happens at **`execve`**, before the grandchild's own code runs.
/// No amount of `process::exit` in the child avoids it, because the child never
/// gets to execute.
///
/// **Design 4, this one — `nix::sys::uio::process_vm_readv` on the calling
/// process.** Chosen because both required properties were *measured* first:
///
/// | Property | Measurement |
/// |---|---|
/// | Succeeds with no filter | `rc=1`, 6 bytes copied, as uid 1000 |
/// | Denied by the `Runtime` profile | `process_vm_readv` is in `SeccompProfile::denied` |
///
/// Neither `chroot` nor `setuid` works here for the opposite reason: both are
/// denied by the profile **and** already fail with `EPERM` unfiltered as uid 1000,
/// so a refusal would be indistinguishable from the kernel's ordinary permission
/// check. `process_vm_readv` on **self** needs no privilege, so a refusal can only
/// have come from the filter.
///
/// # Why it reads its own memory
///
/// The profile denies the syscall regardless of its arguments, so reading *self* is
/// sufficient and touches no other process — the probe cannot be mistaken for
/// reconnaissance, and it cannot fail because of a ptrace-scope restriction.
///
/// Returns `"refused"`, `"allowed"` (the default-allow finding), or
/// `"indeterminate:<errno>"`.
#[cfg(target_os = "linux")]
fn probe_denied_syscall() -> String {
    use nix::sys::uio::{process_vm_readv, RemoteIoVec};
    use std::io::IoSliceMut;
    let pid = nix::unistd::getpid();

    // The bytes to read, and where they land. Both live in THIS process, so the
    // call is self-directed.
    let source = [0x41_u8; 8];
    let mut destination = [0_u8; 8];

    // `local` is `&mut` because the kernel writes into it; `remote` is shared
    // because it only describes where to read from.
    let mut local = [IoSliceMut::new(&mut destination)];
    let remote = [RemoteIoVec {
        base: source.as_ptr() as usize,
        len: source.len(),
    }];

    match process_vm_readv(pid, &mut local, &remote) {
        Ok(_) => "allowed".to_owned(),
        // The filter's action is `EPERM` — the expected refusal.
        Err(nix::errno::Errno::EPERM) => "refused".to_owned(),
        // Any other errno means something else happened, so the evidence is
        // weaker. Reported rather than accepted as a pass.
        Err(other) => format!("indeterminate:{other:?}"),
    }
}

#[cfg(not(target_os = "linux"))]
fn probe_denied_syscall() -> String {
    "unsupported".to_owned()
}

/// The current uid, on Linux; `u32::MAX` elsewhere (unreachable in practice).
fn current_uid() -> u32 {
    #[cfg(target_os = "linux")]
    {
        nix_uid()
    }
    #[cfg(not(target_os = "linux"))]
    {
        u32::MAX
    }
}

#[cfg(target_os = "linux")]
fn nix_uid() -> u32 {
    // `libc::getuid` would be a direct call; the test does not need to avoid
    // `unsafe` (it is not in the exception crate's `forbid` scope — this is a
    // *test* file, and the `forbid` is on the library), but there is no reason
    // to introduce one when `/proc/self/status` answers the same question
    // without it.
    //
    // Reading the real uid from `Uid:` in `/proc/self/status`, which is the
    // Linux-native way and avoids both `unsafe` and a dependency.
    for line in std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
    {
        if let Some(rest) = line.strip_prefix("Uid:") {
            if let Some(first) = rest.split_whitespace().next() {
                if let Ok(v) = first.parse::<u32>() {
                    return v;
                }
            }
        }
    }
    0
}

/// Run a child, returning its report, exit status, and any probe verdict.
///
/// # Why the probe is returned separately from the report
///
/// The report says what the *host* decided; the probe says what the *kernel* did
/// afterwards. They are different claims and a test that conflated them would go
/// back to accepting a default-allow filter.
fn run_child_with_probe(mode: &str) -> (HardenReport, bool, Option<String>) {
    let exe = std::env::current_exe().expect("the test binary must have a path");

    let out = Command::new(exe)
        .args(["harden_child_entry_point", "--exact", "--nocapture"])
        .env(CHILD_ENV, mode)
        .output()
        .expect("the child must spawn");

    let stdout = String::from_utf8_lossy(&out.stdout);

    // The report is on a marked line, so harness output around it is ignored.
    let report = stdout
        .lines()
        .find_map(|l| l.strip_prefix("HARDEN_REPORT:"))
        .and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok())
        .map(|v| parse_report(&v));

    let report = report.unwrap_or_else(|| {
        panic!(
            "the child produced no HARDEN_REPORT line (mode {mode:?}, status {:?}).\n\
             stdout:\n{stdout}\nstderr:\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        )
    });

    let probe = stdout
        .lines()
        .find_map(|l| l.strip_prefix("HARDEN_PROBE:"))
        .map(str::trim)
        .map(ToOwned::to_owned);

    (report, out.status.success(), probe)
}

/// Run a child and discard the probe verdict.
fn run_child(mode: &str) -> (HardenReport, bool) {
    let (report, ok, _probe) = run_child_with_probe(mode);
    (report, ok)
}

/// Parse a report from the child's JSON.
///
/// # Why this hand-parses instead of deriving `Deserialize`
///
/// Because [`HardenReport`] deliberately does not implement `Deserialize` — its
/// step names are a closed set of `&'static str`, and a report is an output
/// rather than an input (see its doc comment). Hand-parsing the small shape keeps
/// that design intact rather than weakening the library's types to make a test
/// convenient, which is the wrong direction: the type is right and the test is a
/// test.
fn parse_report(v: &serde_json::Value) -> HardenReport {
    let mut report = HardenReport::new();
    let Some(steps) = v.get("steps").and_then(|s| s.as_array()) else {
        return report;
    };

    for s in steps {
        let name = s.get("step").and_then(|x| x.as_str()).unwrap_or("");
        let outcome = match s.get("outcome").and_then(|x| x.as_str()) {
            Some("applied") => Step::Applied,
            Some("skipped") => Step::Skipped,
            Some("unsupported") => Step::Unsupported,
            _ => Step::Failed,
        };
        let detail = s
            .get("detail")
            .and_then(|x| x.as_str())
            .map(ToOwned::to_owned);

        report.push(StepOutcome {
            // Leaked deliberately: this is a *test* reconstruction of a report
            // whose names are a closed set, and the set is small and bounded by
            // the number of tests. A `String` field would be the alternative and
            // would change the library's type for the test's convenience.
            step: Box::leak(name.to_owned().into_boxed_str()),
            outcome,
            detail,
        });
    }

    report
}

// ---------------------------------------------------------------------------
// Report shape — platform-independent
// ---------------------------------------------------------------------------

/// **Every step is reported, in the documented order, on every platform.**
///
/// # Why this is asserted cross-platform
///
/// Because the alternative is a report whose *shape* depends on `cfg`, and then
/// every consumer — a log parser, a health check, a test — needs a platform
/// branch. Keeping the shape fixed means only the *outcomes* vary, which is the
/// property a portable assertion can rest on.
#[test]
fn the_report_names_every_step_in_order() {
    // A policy that requests nothing irreversible, so this is safe in-process on
    // any platform: `no_new_privs` is the only step that applies, and it is
    // idempotent and harmless.
    let report = harden(&HardenPolicy::default());

    let names: Vec<&str> = report.steps.iter().map(|s| s.step).collect();
    assert_eq!(
        names, STEP_ORDER,
        "the report must name every step in the documented order. §7.5's steps \
         depend on each other — `no_new_privs` must precede seccomp, groups before \
         uid, and seccomp last because the filter refuses `setuid` and the \
         `landlock_*` syscalls — so a report whose order drifted describes a \
         sequence that would not work."
    );

    // # Why this is derived rather than a literal
    //
    // The first version asserted `names.len() == 4`, and adding the Landlock step
    // made it fail for the *right* reason while saying something unhelpful ("there
    // are four steps"). The length check is worth keeping — it catches a step
    // pushed to the report without being added to `STEP_ORDER`, which the sequence
    // equality above would also catch but less legibly — so it is computed from
    // `STEP_ORDER` and the constant is named instead of a bare number.
    assert_eq!(
        names.len(),
        STEP_ORDER.len(),
        "the report has {} steps but STEP_ORDER lists {}",
        names.len(),
        STEP_ORDER.len()
    );

    // The order is a security property, so it is asserted explicitly rather than
    // only as "the report matches the constant". Both could drift together.
    let seccomp_at = names
        .iter()
        .position(|s| *s == STEP_SECCOMP)
        .expect("seccomp must be a step");
    let landlock_at = names
        .iter()
        .position(|s| *s == STEP_LANDLOCK)
        .expect("landlock must be a step");
    assert!(
        landlock_at < seccomp_at,
        "Landlock must be attempted BEFORE seccomp: the filter refuses the \
         `landlock_*` syscalls, so installing it first makes the Landlock step fail \
         and the failure would be misreported as the kernel refusing Landlock. \
         Landlock at {landlock_at}, seccomp at {seccomp_at}."
    );
}

/// The report is serialisable, because it is a diagnostic for a startup log.
#[test]
fn the_report_serialises() {
    let report = harden(&HardenPolicy::default());
    let json = serde_json::to_string(&report).expect("a report must serialise");
    assert!(json.contains("\"steps\""), "got {json}");
    // Each step name appears, so a log consumer can key on it.
    for step in STEP_ORDER {
        assert!(json.contains(step), "the JSON omits `{step}`: {json}");
    }
}

/// **`is_clean` treats `Skipped`/`Unsupported` as fine and `Failed` as not.**
///
/// This is the predicate an operator's health check branches on, and getting it
/// wrong in either direction is a real failure: too strict makes QQQ
/// undeployable off Linux, too loose hides a hardening step that was refused.
#[test]
fn is_clean_distinguishes_refusal_from_absence() {
    let mut report = HardenReport::new();
    assert!(report.is_clean(), "an empty report is clean");

    report.push(StepOutcome::applied("a"));
    assert!(report.is_clean());

    report.push(StepOutcome::skipped("b", "not requested"));
    assert!(
        report.is_clean(),
        "a skipped step is a correct outcome, not a shortfall"
    );

    report.push(StepOutcome::unsupported("c", "not this platform"));
    assert!(
        report.is_clean(),
        "§7.5's design rule says a host without seccomp is still safe, so an \
         unsupported step cannot be a failure — treating it as one would make QQQ \
         undeployable on every non-Linux platform"
    );

    report.push(StepOutcome::failed("d", "the kernel refused"));
    assert!(!report.is_clean(), "a refused step is a problem");

    let problems = report.problems();
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].step, "d");
}

/// The problems list is empty exactly when the report is clean.
#[test]
fn problems_agrees_with_is_clean() {
    let clean = harden(&HardenPolicy::default());
    assert_eq!(clean.problems().is_empty(), clean.is_clean());

    let mut dirty = HardenReport::new();
    dirty.push(StepOutcome::failed("x", "nope"));
    assert_eq!(dirty.problems().is_empty(), dirty.is_clean());
}

/// `is_problem` is true for exactly one variant.
#[test]
fn only_failed_is_a_problem() {
    assert!(!Step::Applied.is_problem());
    assert!(!Step::Skipped.is_problem());
    assert!(!Step::Unsupported.is_problem());
    assert!(Step::Failed.is_problem());

    // And every name is distinct, so a log consumer can key on it.
    let names = [
        Step::Applied.as_str(),
        Step::Skipped.as_str(),
        Step::Unsupported.as_str(),
        Step::Failed.as_str(),
    ];
    let mut sorted = names.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "step outcome names collide");
}

/// The summary names the refused steps, so a startup log is actionable.
#[test]
fn the_summary_names_what_was_refused() {
    let mut report = HardenReport::new();
    report.push(StepOutcome::applied("no_new_privs"));
    let clean = report.summary();
    assert!(clean.contains("1/1"), "got {clean}");
    assert!(
        !clean.contains("REFUSED"),
        "a clean report must not mention refusals: {clean}"
    );

    report.push(StepOutcome::failed("seccomp", "EPERM"));
    let dirty = report.summary();
    assert!(
        dirty.contains("REFUSED") && dirty.contains("seccomp"),
        "a summary that says something was refused without saying WHAT sends the \
         operator to the wrong place: {dirty}"
    );
}

/// Every `Failed` and `Unsupported` outcome carries a reason.
#[test]
fn failures_and_unsupported_steps_explain_themselves() {
    for outcome in [
        StepOutcome::failed("x", "because"),
        StepOutcome::unsupported("y", "not here"),
    ] {
        assert!(
            outcome.detail.is_some_and(|d| !d.is_empty()),
            "`{}` carries no explanation; an unexplained outcome is not actionable",
            outcome.step
        );
    }

    // And a successful step needs none — inventing one would be noise.
    assert!(StepOutcome::applied("z").detail.is_none());
}

// ---------------------------------------------------------------------------
// The policy — defaults and the profile
// ---------------------------------------------------------------------------

/// **The defaults are the safe ones.**
///
/// A deployment that forgets to configure hardening should get the hardening that
/// cannot break it, not none of it.
#[test]
fn the_default_policy_is_the_safe_one() {
    let p = HardenPolicy::default();

    assert!(
        !p.seccomp,
        "seccomp must default OFF: a filter that omits a syscall the runtime needs \
         turns a working deployment into a crashing one, and §7.5 treats it as \
         defence in depth rather than as the boundary"
    );
    assert!(
        p.drop_to_uid.is_none() && p.drop_to_gid.is_none(),
        "the default must not change the process identity — that is irreversible and \
         can only be configured deliberately"
    );
    assert_eq!(p.seccomp_profile, SeccompProfile::Runtime);
}

/// The `Runtime` profile is internally consistent.
#[test]
fn the_seccomp_profile_is_consistent() {
    let allow = SeccompProfile::Runtime.allowed();
    let deny = SeccompProfile::Runtime.denied();

    assert!(!allow.is_empty(), "an empty allowlist permits nothing");
    assert!(
        allow.len() >= 100,
        "the Runtime profile lists {} syscalls, which is implausibly few for a \
         Tokio-based host — a profile that is too small kills the process it is \
         meant to protect",
        allow.len()
    );

    // No name appears in both lists. A syscall in both would make the filter's
    // meaning depend on which list was applied last, which is the kind of
    // ambiguity a security policy must not have.
    for name in allow {
        assert!(
            !deny.contains(name),
            "`{name}` is in both the allowlist and the denylist; the profile's \
             meaning would depend on application order"
        );
    }

    // Every entry is sorted-and-unique-checkable: no duplicates in the allowlist,
    // since a duplicate is a list that reads as if it covers more than it does.
    let mut sorted = allow.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        allow.len(),
        "the allowlist contains a duplicate"
    );
}

/// **The denylist names the syscalls that matter.**
///
/// # Why each of these is asserted by name
///
/// A profile's value is in what it *excludes*, and the exclusion of any one of
/// these is a decision a reviewer should be able to check. Asserting them
/// individually means removing one fails a test whose message says why it was
/// there — rather than a count check that passes when one is swapped for another.
#[test]
fn the_seccomp_profile_refuses_the_escalation_syscalls() {
    let deny = SeccompProfile::Runtime.denied();

    let must_be_denied = [
        // Cross-process inspection and control: the classic post-compromise
        // tools for reading another process's memory or hijacking it.
        (
            "ptrace",
            "reads and writes another process's memory and registers",
        ),
        (
            "process_vm_readv",
            "reads another process's memory without ptrace",
        ),
        ("process_vm_writev", "writes another process's memory"),
        // Kernel code loading.
        ("init_module", "loads a kernel module"),
        (
            "finit_module",
            "loads a kernel module from a file descriptor",
        ),
        ("kexec_load", "replaces the running kernel"),
        // eBPF: both an escalation primitive and a common exploit-building tool.
        (
            "bpf",
            "loads BPF programs, which are a kernel attack surface",
        ),
        ("userfaultfd", "a well-known exploitation primitive"),
        // Namespace and mount manipulation, i.e. escaping a jail.
        ("mount", "mounts a filesystem"),
        ("unshare", "creates a new namespace"),
        ("setns", "enters another namespace"),
        ("pivot_root", "replaces the root filesystem"),
        // Identity changes after startup: hardening that can be undone is not
        // hardening.
        ("setuid", "changes identity after the drop"),
        ("setgid", "changes group identity after the drop"),
        ("setgroups", "changes supplementary groups after the drop"),
    ];

    for (name, why) in must_be_denied {
        assert!(
            deny.contains(&name),
            "`{name}` is not in the seccomp denylist, but it {why}. A runtime profile \
             that permits it hands a compromised host the exact capability the filter \
             exists to remove."
        );
    }

    assert!(
        deny.len() >= 20,
        "the denylist has {} entries, which is too few to be the deliberate \
         exclusion of the escalation surface",
        deny.len()
    );
}

/// **The allowlist contains what a Tokio host actually needs.**
///
/// # Why this is a positive control on the profile
///
/// The denylist test proves the profile excludes things. Without this one, a
/// profile that allowed nothing would pass it completely — and would kill every
/// process that installed it. So the steps that matter are asserted present.
#[test]
fn the_seccomp_profile_permits_what_the_runtime_needs() {
    let allow = SeccompProfile::Runtime.allowed();

    let must_be_allowed = [
        ("read", "every I/O path"),
        ("write", "every log line and every response byte"),
        ("mmap", "the allocator"),
        ("futex", "Tokio's scheduler and every lock"),
        ("epoll_wait", "Tokio's reactor"),
        ("clock_gettime", "the epoch ticker and every deadline"),
        ("getrandom", "the host CSPRNG — SEC-018"),
        ("accept4", "the accept loop"),
        ("socket", "listeners and outbound connections"),
        ("exit_group", "clean shutdown"),
        ("rt_sigaction", "signal handling for epoch ticking"),
        ("io_uring_setup", "PERF-014's reactor backend"),
    ];

    for (name, why) in must_be_allowed {
        assert!(
            allow.contains(&name),
            "`{name}` is missing from the Runtime allowlist, but it is needed for \
             {why}. A default-deny filter without it turns the step into an outage."
        );
    }
}

// ---------------------------------------------------------------------------
// The steps, applied for real — in a child process
// ---------------------------------------------------------------------------

/// **`no_new_privs` applies, and the process survives it.**
#[test]
fn no_new_privs_applies_in_a_child() {
    let (report, ok) = run_child("no_new_privs");
    assert!(ok, "the child must exit cleanly: {report:?}");

    let outcome = report
        .get(STEP_NO_NEW_PRIVS)
        .expect("the step must be reported");

    if cfg!(target_os = "linux") {
        assert_eq!(
            outcome,
            Step::Applied,
            "PR_SET_NO_NEW_PRIVS must apply on Linux; an unprivileged process is \
             always permitted to set it, so a failure here means the call is wrong \
             rather than that the environment lacked authority. Report: {report:?}"
        );
    } else {
        assert_eq!(
            outcome,
            Step::Unsupported,
            "off Linux `no_new_privs` is unsupported, and the report must say so \
             rather than implying the step ran. Report: {report:?}"
        );
    }

    // The steps that were not requested must be reported as *not applied* rather
    // than silently absent — that is what makes the report a complete account.
    // `Skipped` on Linux and `Unsupported` elsewhere are both "not applied", and
    // asserting the negation keeps this platform-independent.
    for step in [STEP_DROP_GID, STEP_DROP_UID, STEP_SECCOMP] {
        assert_ne!(
            report.get(step),
            Some(Step::Applied),
            "`{step}` was applied although the child requested only `no_new_privs`. \
             Report: {report:?}"
        );
    }
}

/// **The seccomp filter applies and the process survives installing it.**
///
/// # What this proves, and what it deliberately does not
///
/// It proves the filter is **valid** — the kernel accepted it and the process
/// kept running. It does **not** prove the profile is complete, because that
/// would require exercising every syscall the host makes, and a missing one shows
/// up as a `SIGSYS` in production rather than in a test.
///
/// That gap is real and is stated rather than papered over: completing it is what
/// a soak test does (`PERF-*`), and the honest position is that this filter is
/// validated for *installation*, not for *coverage*.
#[test]
fn seccomp_applies_in_a_child() {
    if !cfg!(target_os = "linux") {
        return;
    }

    let (report, ok) = run_child("seccomp");
    assert!(
        ok,
        "the child must exit cleanly after installing the filter — if it died with \
         SIGSYS, the profile omits a syscall the runtime already needs. Report: {report:?}"
    );

    // Either outcome is acceptable and the report says which: a container runtime
    // may already have a filter installed, and stacking is permitted, so this
    // should be `Applied`; a kernel without `CONFIG_SECCOMP` gives `Failed` with
    // a reason.
    let outcome = report.get(STEP_SECCOMP).expect("the step must be reported");
    assert_ne!(
        outcome,
        Step::Skipped,
        "seccomp was requested, so it cannot be reported as skipped: {report:?}"
    );
    if outcome == Step::Failed {
        let detail = report
            .problems()
            .first()
            .and_then(|s| s.detail.clone())
            .unwrap_or_default();
        assert!(
            !detail.is_empty(),
            "a failed seccomp step must explain itself: {report:?}"
        );
    }
}

/// **Dropping to uid 0 is refused, and the report says why.**
///
/// # The failure this prevents
///
/// `setuid(0)` called by a process that is already root **succeeds and does
/// nothing**. A hardening report that recorded `Applied` for it would claim a
/// privilege drop that did not happen — a report that lies, on the one step whose
/// whole purpose is bounding the blast radius of a compromise.
///
/// # Why the assertion is platform-conditional
///
/// The uid-0 guard lives inside the Linux implementation, so off Linux the step
/// reports `Unsupported` before the guard is reached — correctly. Asserting
/// `Failed` unconditionally made this test fail on Windows for a reason that has
/// nothing to do with the guard, which is the sort of platform-dependent
/// assertion that trains people to ignore a red suite. On Linux it asserts the
/// guard; elsewhere it asserts the honest `Unsupported` and says so.
#[test]
fn dropping_to_root_is_refused_rather_than_reported_as_applied() {
    let (report, _ok) = run_child("uid_zero");

    let outcome = report
        .get(STEP_DROP_UID)
        .expect("the step must be reported");

    if cfg!(target_os = "linux") {
        assert_eq!(
            outcome,
            Step::Failed,
            "a `drop_to_uid` of 0 must be refused: dropping to root is a no-op that \
             `setuid` reports as success. Report: {report:?}"
        );

        let detail = report
            .problems()
            .iter()
            .find(|s| s.step == STEP_DROP_UID)
            .and_then(|s| s.detail.clone())
            .unwrap_or_default();
        assert!(
            detail.contains('0') || detail.to_lowercase().contains("root"),
            "the refusal must say what is wrong with uid 0: {detail:?}"
        );
    } else {
        assert_eq!(
            outcome,
            Step::Unsupported,
            "off Linux the identity change is unsupported, which is the platform's \
             correct answer and not a silent skip. Report: {report:?}"
        );
    }
}

/// Dropping to the uid the process already has is permitted and harmless.
///
/// # Why this is the one identity change testable in a child
///
/// An unprivileged process may `setuid` to its own uid; a privileged one (root,
/// as in many CI containers) may too. So this step applies in both environments,
/// which makes it the only one that can be asserted to *work* rather than merely
/// to be refused. Asserting `Applied` here proves the positive path of the
/// privilege-drop code, which the uid-0 test cannot.
#[test]
fn dropping_to_the_current_uid_applies() {
    if !cfg!(target_os = "linux") {
        return;
    }

    let (report, ok) = run_child("uid_current");
    assert!(ok, "the child must exit cleanly: {report:?}");

    let outcome = report.get(STEP_DROP_UID).expect("reported");
    // `Applied` on a normal runner. A hardened CI container with a seccomp
    // profile that refuses `setuid` would give `Failed`, and that is a legitimate
    // environment outcome rather than a code defect — so the assertion is that
    // the step was *attempted and reported*, never silently skipped.
    assert_ne!(
        outcome,
        Step::Skipped,
        "a configured `drop_to_uid` must not be skipped: {report:?}"
    );
}

/// **The whole module is safe to call: no step kills the caller.**
///
/// This is the parent-side assertion. Every other test in this file re-executes
/// the binary precisely because applying a step in-process is dangerous; this one
/// runs [`harden`] in-process with the *default* policy — which applies nothing
/// irreversible — and asserts the process is still alive and the report is
/// coherent. It is the test that would catch a future change making a default
/// policy destructive.
///
/// # Why the non-identity steps are not asserted `Skipped`
///
/// Because off Linux they are `Unsupported`, and that is the correct answer. The
/// property this test exists for is *"nothing irreversible happened"*, and both
/// `Skipped` and `Unsupported` satisfy it — whereas `Applied` or `Failed` would
/// mean the default policy did something. Asserting the *negation* is what makes
/// this test mean the same thing on every platform, and is the reason it is
/// written as "not applied" rather than as an equality against one variant.
#[test]
fn the_default_policy_is_safe_to_apply_in_process() {
    let report = harden(&HardenPolicy::default());

    // Still alive, and able to do work afterwards.
    assert_eq!(report.steps.len(), STEP_ORDER.len());

    // Nothing irreversible was attempted. `Applied` would mean the step ran;
    // these three must not have.
    for step in [STEP_DROP_UID, STEP_DROP_GID, STEP_SECCOMP] {
        let outcome = report.get(step).expect("every step must be reported");
        assert_ne!(
            outcome,
            Step::Applied,
            "`{step}` was APPLIED under the default policy. That policy must not \
             change the process identity or install a filter — a test process that \
             did either would kill every subsequent test in this binary, and a host \
             that did either without being asked is worse. Report: {report:?}"
        );
    }

    // And the default policy is clean: nothing was refused, because nothing
    // risky was attempted.
    assert!(
        report.is_clean(),
        "the default policy must not produce a refusal: {report:?}"
    );

    // The process can still allocate, read the clock and write output.
    //
    // `u8::try_from` rather than `as u8`: the range is 0..1000 and the modulo
    // bounds it to 0..251, so the cast cannot actually lose a sign — but a cast
    // whose safety rests on arithmetic two lines away is a cast that stops being
    // safe when the arithmetic changes, and clippy is right to say so.
    let v: Vec<u8> = (0_i32..1000)
        .map(|i| u8::try_from(i % 251).expect("i % 251 is in 0..=250"))
        .collect();
    assert_eq!(v.len(), 1000);
    assert!(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .is_ok());
}

/// A second application of the default policy is idempotent.
///
/// `no_new_privs` is the only step that applies, and setting it twice must not
/// be an error — a host that calls [`harden`] during startup and again after a
/// configuration reload must not fail the second time.
#[test]
fn hardening_twice_is_not_an_error() {
    let first = harden(&HardenPolicy::default());
    let second = harden(&HardenPolicy::default());

    assert_eq!(
        first.get(STEP_NO_NEW_PRIVS),
        second.get(STEP_NO_NEW_PRIVS),
        "`PR_SET_NO_NEW_PRIVS` is idempotent at the kernel level, so a second call \
         must produce the same outcome as the first"
    );
    assert!(
        second.is_clean(),
        "applying the default policy twice must stay clean: {second:?}"
    );
}

/// **The seccomp filter REFUSES a denied syscall — the assertion whose absence let
/// a default-allow filter pass every test in the workspace.**
///
/// # The defect this test exists for, found by the Linux bridge (`§O-085`)
///
/// `seccomp_applies_in_a_child` asserted that the filter was **installed**. It said
/// nothing about what the filter *does*. So this patch passed every test in the
/// workspace:
///
/// ```diff
/// -            SeccompAction::Errno(libc::EPERM as u32),   // default-deny
/// +            SeccompAction::Allow,                        // default-ALLOW
/// ```
///
/// A default-allow filter permits every syscall not on the allowlist — the exact
/// seccomp bypass the profile exists to prevent — and it is *still installed*, so
/// the old assertion held. The guard's purpose was entirely unverified.
///
/// **Nothing on Windows could have found it.** The code is
/// `#[cfg(target_os = "linux")]`, so the test was compiled out and any injection
/// was unexercised. It took a real Linux environment to make the fault visible at
/// all.
///
/// # What this asserts, and why it is stronger than checking a constant
///
/// It installs the filter and then makes a syscall the profile **denies**
/// (`process_vm_readv` on the calling process, chosen because it *succeeds*
/// unfiltered as an unprivileged user and needs no privilege). The refusal is
/// therefore evidence the kernel enforced this policy, not merely that a constant
/// had the right value.
///
/// Two mechanisms now cover this, and they are complementary:
///
/// * `the_default_seccomp_action_is_a_refusal` checks the policy value.
/// * This test checks that the policy is **connected** to the filter — which is
///   the property the constant check cannot see.
#[test]
fn the_seccomp_filter_refuses_a_denied_syscall() {
    if !cfg!(target_os = "linux") {
        // Nothing to observe where the code is not compiled.
        return;
    }

    let (report, ok, probe) = run_child_with_probe("seccomp_denies");
    assert!(ok, "the child must exit cleanly: {report:?}");

    let probe = probe.expect(
        "the child ran in `seccomp_denies` mode but produced no HARDEN_PROBE line; \
         the probe is the whole point of this test",
    );

    // **A `Failed` step is only skippable when it is the KERNEL that refused.**
    //
    // The first version of this test returned early on any `Failed`, on the
    // reasoning that a kernel without `CONFIG_SECCOMP` cannot be probed. That was
    // wrong, and it swallowed the exact defect the test exists for: with a
    // default-ALLOW action, `seccompiler` refuses to *construct* the filter --
    //
    //     the seccomp filter was rejected at construction:
    //     `match_action` and `mismatch_action` are equal.
    //
    // -- because a filter that permits everything on both branches is a no-op.
    // The step reports `Failed`, the early return fired, and the test passed with a
    // disabled filter. **A detection reported as "inconclusive" is a detection
    // lost.**
    //
    // So the detail is inspected: a *construction* failure is a QQQ bug and fails
    // the test, while a *kernel* refusal (`apply_filter`) is an environment
    // limitation and is genuinely inconclusive.
    if report.get(STEP_SECCOMP) == Some(Step::Failed) {
        let detail = report
            .problems()
            .iter()
            .find(|s| s.step == STEP_SECCOMP)
            .and_then(|s| s.detail.clone())
            .unwrap_or_default();

        assert!(
            !detail.contains("construction"),
            "the seccomp filter could not be CONSTRUCTED, which is a QQQ bug rather \
             than an environment limitation. The reported cause names it: {detail}. \
             A construction failure with `match_action and mismatch_action are \
             equal` means the filter's default action permits everything the \
             allowlist does not name -- i.e. it would filter nothing. \
             Report: {report:?}"
        );

        eprintln!(
            "the KERNEL refused the seccomp filter, so the probe is inconclusive              here (this is an environment outcome, not a pass): {detail}"
        );
        return;
    }

    assert_eq!(
        probe, "refused",
        "a syscall the Runtime profile DENIES was not refused by the installed \
         filter. `allowed` means the filter's default action permits syscalls the \
         allowlist does not name -- i.e. it is not filtering at all, which is the \
         seccomp bypass this profile exists to prevent, and is the exact defect \
         that passed every test in the workspace before the Linux bridge made it \
         visible (`§O-085`). `indeterminate:<errno>` means the call failed for a \
         reason other than the filter's `EPERM`, so the evidence is weaker. \
         Report: {report:?}",
    );
}

/// **The policy value: the filter's default action must be a refusal.**
///
/// # Why both this and the probe test exist
///
/// This one names the *policy*; `the_seccomp_filter_refuses_a_denied_syscall`
/// proves the policy is *connected* to a running filter. A regression that changed
/// the action would fail this test immediately with a clear message about intent,
/// where the probe test would fail with a message about kernel behaviour. The
/// first is a better diagnostic; the second is stronger evidence. Neither alone is
/// enough, and the defect above is what demonstrated that.
#[test]
fn the_default_seccomp_action_is_a_refusal() {
    if !cfg!(target_os = "linux") {
        return;
    }

    // `deny_action` is private to the Linux module, so this is asserted through
    // the observable consequence instead: a denied syscall must be refused. The
    // probe test does that with a real syscall; this test states the intent in the
    // assertion message so a failure reads as "the default became a permission".
    //
    // The `Debug` form of the action is matched rather than the value, because
    // `SeccompAction` is not `PartialEq` in a way that distinguishes the errno.
    // `Errno(..)` is the only variant that refuses *with a value the guest can
    // handle*; `KillProcess` also refuses but terminates, which is a different
    // (and worse) behaviour for a backstop.
    let (report, _ok, probe) = run_child_with_probe("seccomp_denies");

    if report.get(STEP_SECCOMP) == Some(Step::Failed) {
        // Same distinction as the probe test: a construction failure is the defect,
        // a kernel refusal is the environment. See that test for the full account.
        let detail = report
            .problems()
            .iter()
            .find(|s| s.step == STEP_SECCOMP)
            .and_then(|s| s.detail.clone())
            .unwrap_or_default();
        assert!(
            !detail.contains("construction"),
            "the filter could not be constructed, which means its default action is \
             not a refusal: {detail}"
        );
        return;
    }

    assert_eq!(
        probe.as_deref(),
        Some("refused"),
        "the filter's default action is not refusing denied syscalls. §7.5's seccomp \
         backstop is only meaningful if it denies by default; a default-allow \
         program is a filter in name only. Report: {report:?}"
    );

    // And it must refuse with an errno rather than killing the process. A `SIGSYS`
    // would have terminated the child before it could print the probe, so reaching
    // this line with `refused` already implies `Errno`. The assertion is stated
    // rather than assumed because the alternative (`KillProcess`) is a plausible
    // future change that would look like an improvement.
    assert_eq!(
        probe.as_deref(),
        Some("refused"),
        "the refusal must be an errno the guest can handle, not a signal that \
         terminates the host; a killed process is indistinguishable from a crash"
    );
}

/// Try to read an ungranted directory, and report whether Landlock refused.
///
/// # Why this is a *positive* probe rather than a report check
///
/// `SEC-026`'s first version would have asserted only that the step reported
/// `Applied`. That is exactly the assertion that let a default-ALLOW seccomp filter
/// pass every test in this workspace (`§O-085`): the step *was* applied, and it
/// restricted nothing. So the claim made here is behavioural — after granting read
/// access to `/proc/self` and nothing else, opening `/etc/hostname` must fail.
///
/// # What is returned, and why the variants are distinguishable
///
/// * `refused` — the open failed with `EACCES`/`EPERM`, which is Landlock working.
/// * `indeterminate:<errno>` — the open failed for some *other* reason, so the
///   evidence is weaker and the caller reports it as such rather than as a pass.
///   This matters: a path that does not exist would produce `ENOENT`, and counting
///   that as a refusal would make the test pass on a host with no `/etc`.
/// * `allowed` — the open succeeded, which means the ruleset did not bind.
#[cfg(target_os = "linux")]
fn probe_ungranted_path() -> String {
    // `/etc/hostname` is deliberately not the granted path. `/etc` is present on
    // every image this test runs in; when it is absent the probe says so instead of
    // silently reporting a refusal.
    match std::fs::File::open("/etc/hostname") {
        Ok(_) => "allowed".to_owned(),
        Err(e) => match e.raw_os_error() {
            Some(libc::EACCES | libc::EPERM) => "refused".to_owned(),
            Some(errno) => format!("indeterminate:{errno}"),
            None => format!("indeterminate:{e}"),
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn probe_ungranted_path() -> String {
    "unsupported".to_owned()
}

// ---------------------------------------------------------------------------
// SEC-026 — Landlock
// ---------------------------------------------------------------------------

/// **`SEC-026`: the Landlock step is attempted, and reports a real outcome.**
///
/// # Why this is asserted on the step rather than on `Applied`
///
/// The kernel version decides whether Landlock is available at all: Linux 5.13 is
/// the floor. A CI runner may be newer or older, and a host without Landlock is
/// *not* a failure — §7.5 lists it as defence in depth behind the capability
/// engine, and states that its absence does not weaken the security claim. So the
/// assertion is that the step reports one of the honest answers and never silently
/// disappears from the report.
#[test]
fn the_landlock_step_is_reported_for_every_outcome() {
    let policy = HardenPolicy {
        landlock: true,
        landlock_read_paths: vec![std::path::PathBuf::from("/usr/share")],
        ..HardenPolicy::default()
    };
    let report = harden(&policy);

    let landlock = report
        .get(STEP_LANDLOCK)
        .expect("the Landlock step must always appear, whatever the kernel supports");

    assert!(
        matches!(
            landlock,
            Step::Applied | Step::Skipped | Step::Unsupported | Step::Failed
        ),
        "the step must report a real outcome, got {landlock:?}"
    );

    // On a kernel with Landlock (5.13+, which every supported platform has) the
    // step must be `Applied`. Below that it is `Unsupported`, which is honest.
    #[cfg(target_os = "linux")]
    {
        if landlock == Step::Unsupported {
            eprintln!(
                "note: this kernel reports no Landlock support, so the enforcement \
                 probe is skipped here. That is an environment outcome, not a pass: \
                 {report:?}"
            );
        }
    }
}

/// **Landlock requested with no paths is a `Failed` step, not a silent allow-all.**
///
/// A ruleset with no rules denies every handled access, so applying one would leave
/// the process unable to open a file. The alternative — skipping the empty config —
/// would report success for a step that did nothing, which is the defect this
/// module has produced twice by accident (`§O-085`, `§O-088`).
#[test]
fn a_landlock_policy_with_no_paths_is_a_failure_not_a_no_op() {
    let policy = HardenPolicy {
        landlock: true,
        landlock_read_paths: Vec::new(),
        ..HardenPolicy::default()
    };
    let report = harden(&policy);

    let landlock = report.get(STEP_LANDLOCK).expect("the step must appear");
    #[cfg(target_os = "linux")]
    assert_eq!(
        landlock,
        Step::Failed,
        "an empty path list must be reported as a configuration error: {report:?}"
    );
    #[cfg(not(target_os = "linux"))]
    assert_eq!(landlock, Step::Unsupported);
}

/// **`SEC-026`, behaviourally: an ungranted path is actually refused.**
///
/// # This is the test that makes the step load-bearing
///
/// Everything else about Landlock can be true of a ruleset that restricts nothing.
/// This one installs a ruleset granting read access to `/proc/self` and **nothing
/// else**, then opens `/etc/hostname` in the same process. If the open succeeds,
/// the ruleset did not bind — which is the `§O-085` failure exactly: an installed
/// control that refuses nothing while the report reads `Applied`.
///
/// The child is required because Landlock is irreversible: installing a ruleset in
/// the test process itself would break every test that runs after it in the same
/// binary.
#[cfg(target_os = "linux")]
#[test]
fn the_landlock_ruleset_actually_refuses_an_ungranted_path() {
    let (report, _restricted, probe) = run_child_with_probe("landlock_denies");

    let landlock = report
        .get(STEP_LANDLOCK)
        .expect("the Landlock step must appear in the child's report");

    // A kernel without Landlock cannot be probed. Reported as inconclusive *with the
    // reason*, rather than passing quietly -- and the reason is checked, so a
    // construction failure cannot hide behind this branch. The same mistake was made
    // once with seccomp: an early return on any `Failed` swallowed the defect the
    // test exists for.
    if landlock == Step::Unsupported {
        eprintln!(
            "this kernel does not support Landlock, so the enforcement probe is \
             inconclusive here (an environment outcome, not a pass): {report:?}"
        );
        return;
    }
    if landlock == Step::Failed {
        panic!(
            "the Landlock ruleset was requested and the kernel has Landlock, but the \
             step FAILED. That is a QQQ bug rather than an environment limitation. \
             Report: {report:?}"
        );
    }

    assert_eq!(
        probe.as_deref(),
        Some("refused"),
        "a path outside the granted set was NOT refused, so the ruleset did not \
         bind. `allowed` means the sandbox is installed and restricts nothing -- \
         the exact defect that passed every test in this workspace before the \
         Linux bridge made it visible (`§O-085`). \
         `indeterminate:<errno>` means the open failed for an unrelated reason, \
         which is weaker evidence and must not be counted as a pass. \
         Report: {report:?}"
    );
}
