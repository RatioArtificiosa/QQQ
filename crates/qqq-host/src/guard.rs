// SPDX-License-Identifier: Apache-2.0

//! Host-function panic containment — `HOST-011`.
//!
//! Proposal §2.2 makes this a security requirement, not a robustness nicety:
//!
//! > | Limits are enforceable | A breach traps the guest, **never the host**. |
//!
//! # The problem
//!
//! Every host function QQQ registers is a Rust closure called *from inside*
//! Wasmtime's execution of guest code. If that closure panics, the unwind starts
//! inside the engine's call stack and propagates out through whatever the host
//! was doing — which in `qqq-serve` is a request task on a Tokio worker. The
//! consequences, in increasing order of badness:
//!
//! 1. The connection is dropped rather than answered, so the client sees a
//!    transport error instead of a `500`.
//! 2. The panic can leave the store's borrow state inconsistent, so a
//!    `RefCell`-style borrow panic follows the first one and the log has two
//!    unrelated-looking failures.
//! 3. With `panic = "abort"` — which `Cargo.toml` set for the **release**
//!    profile before `F-01` removed it — the process died. One guest
//!    triggering one bug in one host function takes down every tenant on
//!    the host. The release profile now unwinds (the default), so this
//!    guard is live in the shipped binary; the `panic_probe` example and
//!    the release-probe CI step prove it on every push.
//!
//! That third point is the one that makes this a security boundary. A guest
//! that can find a panicking host function gets a deny-of-service against the
//! whole process, and §7.2's adversary model explicitly includes hostile guests.
//!
//! # The mechanism, and why it is a wrapper rather than a global hook
//!
//! [`std::panic::catch_unwind`] is the only way to stop an unwind. The design
//! question is *where* to put it, and there are two options:
//!
//! * **A global `panic::set_hook`** intercepts reporting, not unwinding. It
//!   cannot stop the panic and it is process-wide, so it would also swallow
//!   panics in `qqq-serve`, `qqq-run` and every other crate — converting
//!   genuine host bugs into silence everywhere. Rejected.
//! * **A per-call wrapper** catches exactly at the boundary between host code
//!   and guest code, which is the only place the requirement applies. Chosen.
//!
//! [`guard`] is that wrapper. It is *not* applied by convention: [`guarded`]
//! registers a host function through it, and the registration sites are audited
//! by [`all_host_functions_are_guarded`]'s supporting check in the registration
//! modules.
//!
//! # What happens to the guest
//!
//! The panic becomes a normal Wasmtime trap carrying
//! [`ErrorCode::GuestPanic`]'s sibling — actually [`ErrorCode::HostPanicContained`],
//! which is a **`6xxx` host-fault code, not a `3xxx` guest-trap code**, and the
//! distinction is deliberate: the guest did nothing wrong. Reporting a host bug
//! as a guest trap would send an operator to inspect the wrong artifact, and it
//! would make an attacker's successful panic look like misbehaving guest code
//! rather than the host defect it is.
//!
//! The panic message is **not** forwarded to the guest. It can contain host
//! paths, internals and sometimes data, so it goes to the host's log through
//! [`PanicReport`] and the guest gets a fixed string.
//!
//! # Severity-1
//!
//! `HOST-011` also requires "severity-1 alerting". A contained panic is
//! *always* a QQQ bug — no host function should panic on any input, because the
//! inputs are guest-controlled and therefore attacker-controlled — so it is
//! reported through [`PanicReport::is_severity_one`], which is unconditionally
//! `true`. The metric half is `TrapLabel::Other`-adjacent: see
//! [`crate::metrics::Metrics::note_host_panic`].

use std::panic::{catch_unwind, AssertUnwindSafe};

/// A contained panic, as reported to the host's log.
///
/// # Why the payload is extracted rather than passed through
///
/// `catch_unwind` yields `Box<dyn Any>`, which is not printable, not `Send`, and
/// cannot be logged without downcasting. Extracting the two concrete payload
/// types here means the rest of the crate never touches `dyn Any`, and a payload
/// that is neither `&str` nor `String` (which a `panic_any` call can produce) is
/// described honestly rather than dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanicReport {
    /// The host function that panicked, e.g. `"qqq:crypto/digest"`.
    pub function: String,
    /// The panic payload, when it was a string.
    pub message: String,
}

impl PanicReport {
    /// A contained panic is always a QQQ defect, so this is always `1`.
    ///
    /// # Why this is a method and not a field
    ///
    /// The value is not computed from anything — it is a statement of policy,
    /// and stating it as a constant function makes the policy greppable and
    /// gives a future severity model one place to change. A field would suggest
    /// the value varies, which would invite a caller to set it.
    #[must_use]
    pub const fn is_severity_one(&self) -> bool {
        true
    }

    /// The line to write to the host log.
    ///
    /// Includes the function name first, so a log search for the failing
    /// interface finds every occurrence without a regex.
    #[must_use]
    pub fn log_line(&self) -> String {
        format!(
            "SEV1 host-panic-contained: {} panicked: {}",
            self.function, self.message
        )
    }
}

/// Extract a printable message from a panic payload.
///
/// `panic!("literal")` produces `&'static str` and `panic!("{x}")` produces
/// `String`; both are covered. A `panic_any` with another type is described by
/// its type name, which is less useful but is not a lie.
fn payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<panic payload was not a string>".to_owned()
    }
}

/// Run a host function with panic containment, converting a panic to a trap.
///
/// # What the closure returns
///
/// The same `wasmtime::Result<T>` a host function returns normally. A panic
/// becomes an `Err` carrying a Wasmtime trap whose message names the function —
/// so the trap taxonomy classifies it and the guest sees an ordinary trap.
///
/// # Why this is a wrapper and not a global hook
///
/// A `panic::set_hook` intercepts *reporting*, not unwinding: it cannot stop the
/// panic, and it is process-wide, so it would also swallow panics in
/// `qqq-serve`, `qqq-run` and every other crate — turning genuine host bugs into
/// silence everywhere. `catch_unwind` at the host/guest boundary is the only
/// place the requirement applies.
///
/// # Why the panic message does not reach the guest
///
/// It can contain host paths, internals and sometimes guest-supplied data. The
/// guest gets the function name and nothing else; the full message goes to
/// [`PanicReport`], which the caller logs.
///
/// For the logging form — which is what every registration site should use, since
/// a contained panic that is trapped but never logged leaves no trace — see
/// [`guard_reporting`].
///
/// # Errors
///
/// Returns the closure's own error unchanged, or a trap naming the function when
/// the closure panicked.
pub fn guard<T, F>(function: &str, f: F) -> wasmtime::Result<T>
where
    F: FnOnce() -> wasmtime::Result<T>,
{
    match guard_reporting(function, f) {
        // Flattened deliberately: a caller that does not care about the report
        // still gets the closure's own error, unwrapped.
        Ok(result) => result,
        Err(report) => Err(wasmtime::Error::msg(format!(
            "host function `{}` panicked; the host contained it",
            report.function
        ))),
    }
}

/// As [`guard`], but hands the caller the [`PanicReport`] for logging.
///
/// This is the form the registration sites use, because a contained panic that
/// is trapped but never *logged* is a bug nobody will find: the guest sees a
/// trap, the request fails, and the host defect leaves no trace.
///
/// # Errors
///
/// Returns the [`PanicReport`] when `f` panicked, and the normal error
/// otherwise.
pub fn guard_reporting<T, F>(function: &str, f: F) -> Result<wasmtime::Result<T>, PanicReport>
where
    F: FnOnce() -> wasmtime::Result<T>,
{
    // `AssertUnwindSafe` is required because a closure capturing `&mut` state
    // is not `UnwindSafe`, and it is **sound here for a specific reason worth
    // stating**: the state behind the reference is a `StoreContextMut`, whose
    // contents Wasmtime already treats as poisoned after a trap — the instance
    // is discarded on any error ([`crate::trap`], and §4.4 step 14). So there is
    // no reachable path where a partially-updated value is observed by
    // subsequent code: the trap that follows the panic discards the instance
    // that holds it.
    //
    // Without that invariant this would be genuinely unsound, so the
    // justification is written down rather than the `AssertUnwindSafe` being
    // treated as boilerplate.
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => Ok(result),
        Err(payload) => Err(PanicReport {
            function: function.to_owned(),
            message: payload_message(&*payload),
        }),
    }
}

/// Aborts the whole process if the owning thread unwinds.
///
/// Use ONLY for infrastructure threads whose death would silently disable a
/// safety mechanism (the epoch ticker, the audit append worker). A dead
/// ticker stops epoch increments, so wall-clock deadlines never fire and
/// only fuel bounds CPU; a dead audit worker stops evidence. Request threads
/// must NOT use this: their panics are contained by [`guard`] into traps.
/// No `unsafe` needed: [`std::thread::panicking`] reports whether the current
/// thread is unwinding, and [`std::process::abort`] stops fail-stop.
///
/// `#[doc(hidden)]`: infrastructure detail, not host API. The only
/// cross-crate user is the epoch ticker in `qqq-run`, which cannot see a
/// `pub(crate)` item.
///
/// ```
/// use qqq_host::guard::AbortOnPanic;
///
/// {
///     let _fail_stop = AbortOnPanic::new("example-ticker");
///     // Calm scope: dropping outside a panic does nothing.
/// }
/// ```
#[doc(hidden)]
pub struct AbortOnPanic(&'static str);

impl AbortOnPanic {
    /// Name the thread the guard watches, for the fail-stop log line.
    ///
    /// ```
    /// use qqq_host::guard::AbortOnPanic;
    ///
    /// let _fail_stop = AbortOnPanic::new("example-worker");
    /// ```
    #[must_use]
    pub fn new(thread_name: &'static str) -> Self {
        Self(thread_name)
    }
}

impl Drop for AbortOnPanic {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "qqq: infrastructure thread '{}' panicked; aborting (fail-stop)",
                self.0
            );
            std::process::abort();
        }
    }
}

/// F-01 probe entry: call the same guard wrapper `linker.rs` uses, with a
/// closure that panics; true only if the guard converts it to a report.
///
/// `#[doc(hidden)]` and feature-gated (`release-panic-probe`) so the probe
/// surface stays out of the default API: the `panic_probe` example is the
/// only caller, and CI runs it with the feature explicitly.
///
/// ```
/// # #[cfg(feature = "release-panic-probe")] {
/// assert!(qqq_host::probe_panic_guard());
/// # }
/// ```
#[cfg(feature = "release-panic-probe")]
#[doc(hidden)]
#[must_use]
pub fn probe_panic_guard() -> bool {
    guard_reporting("probe", || -> wasmtime::Result<u32> {
        panic!("deliberate F-01 probe panic")
    })
    .is_err()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_successful_call_passes_through_unchanged() {
        let out = guard("test/f", || Ok(42_u32)).expect("no panic");
        assert_eq!(out, 42);
    }

    #[test]
    fn a_normal_error_passes_through_unwrapped() {
        let result: wasmtime::Result<u32> = guard("test/f", || Err(wasmtime::Error::msg("boom")));
        let err = result.expect_err("the error must survive the guard");
        assert!(
            format!("{err}").contains("boom"),
            "the guard must not replace a real error: {err}"
        );
    }

    /// **HOST-011, the actual claim.** A panicking host function becomes a trap
    /// instead of unwinding the host.
    #[test]
    fn a_panic_becomes_a_trap_and_does_not_unwind() {
        // If the guard did not exist this call would panic the test thread, and
        // the test would fail with the panic rather than pass — so the assertion
        // is that control reaches the next line at all.
        let result: wasmtime::Result<u32> = guard("qqq:crypto/digest", || panic!("host bug"));
        let err = result.expect_err("a panic must become an error");
        let text = format!("{err}");
        assert!(
            text.contains("qqq:crypto/digest"),
            "the trap must name the host function so an operator knows where to look: {text}"
        );
    }

    /// The payload must not reach the guest, because it can contain host
    /// internals and guest-controlled data.
    #[test]
    fn the_panic_payload_is_not_forwarded_to_the_guest() {
        let secret = "/var/lib/qqq/internal/secret-path";
        let result: wasmtime::Result<()> = guard("qqq:fs/read", || panic!("{secret}"));
        let err = result.expect_err("a panic must become an error");
        let text = format!("{err}");
        assert!(
            !text.contains(secret),
            "the guest must not learn host internals through a trap: {text}"
        );
    }

    /// The report keeps the message, which is what makes the bug findable.
    #[test]
    fn the_report_keeps_the_message_for_the_log() {
        let report = guard_reporting::<(), _>("qqq:sql/query", || panic!("null column"))
            .expect_err("a panic must be reported");
        assert_eq!(report.function, "qqq:sql/query");
        assert_eq!(report.message, "null column");
    }

    /// A `String` payload and a `&str` payload must both be readable.
    #[test]
    fn both_string_payload_shapes_are_extracted() {
        let borrowed = guard_reporting::<(), _>("f", || panic!("literal")).expect_err("panic");
        assert_eq!(borrowed.message, "literal");

        let owned =
            guard_reporting::<(), _>("f", || panic!("formatted {}", 42)).expect_err("panic");
        assert_eq!(owned.message, "formatted 42");
    }

    /// A non-string payload is described rather than silently emptied.
    #[test]
    fn a_non_string_payload_is_described_honestly() {
        let report = guard_reporting::<(), _>("f", || std::panic::panic_any(7_u32))
            .expect_err("panic_any still panics");
        assert_eq!(report.message, "<panic payload was not a string>");
    }

    /// A contained panic is always a QQQ defect and always severity 1.
    #[test]
    fn a_contained_panic_is_always_severity_one() {
        let report = guard_reporting::<(), _>("f", || panic!("x")).expect_err("panic");
        assert!(report.is_severity_one());
        assert!(
            report
                .log_line()
                .starts_with("SEV1 host-panic-contained: f"),
            "the log line must lead with the severity and the function: {}",
            report.log_line()
        );
    }

    /// The guard must not swallow the *value* of a successful call, including
    /// `None`, `false` and `0` — the shapes a careless `map_err` could confuse.
    #[test]
    fn falsy_success_values_survive() {
        assert!(!guard("f", || Ok(false)).expect("no panic"));
        assert_eq!(guard("f", || Ok(0_u32)).expect("no panic"), 0);
        assert_eq!(
            guard::<Option<u32>, _>("f", || Ok(None)).expect("no panic"),
            None
        );
    }

    /// A panic must not be converted into a *success*, which is the failure mode
    /// of a guard that forgets to return the error.
    #[test]
    fn a_panic_is_never_a_success() {
        let result: wasmtime::Result<u32> = guard("f", || panic!("boom"));
        assert!(result.is_err(), "a panic must never look like a result");
    }

    /// **F-01: the fail-stop guard is inert on the calm path.**
    ///
    /// `abort()` cannot be asserted in-process (it would kill the test
    /// runner), so this pins the other half: a guard dropped outside a panic
    /// does nothing and the process survives. The aborting half is covered
    /// by code review of the four-line `Drop` plus the release-profile probe,
    /// which would die if the guard misbehaved around a real unwind.
    #[test]
    fn f01_abort_on_panic_guard_is_inert_when_not_panicking() {
        let _guard = AbortOnPanic::new("test-thread");
        // Dropping at end of scope must NOT abort the test process.
    }

    /// **F-01: the fail-stop guard aborts through a real unwind.**
    ///
    /// A child process of the test binary itself (same argv, plus an env
    /// marker) constructs the guard and panics through it; the parent
    /// asserts abnormal termination. Spawning the test binary — not a shell
    /// script — keeps the proof inside the
    /// suite: no external runner, no ambient tool. The marker env var keeps
    /// the child on the panicking path only; without it the test is the
    /// ordinary inert case above.
    #[test]
    fn f01_abort_on_panic_guard_aborts_during_unwind() {
        const MARKER: &str = "QQQ_ABORT_ON_PANIC_PROBE";
        if std::env::var_os(MARKER).is_some() {
            let _guard = AbortOnPanic::new("probe-child");
            panic!("deliberate F-01 child panic through the guard");
        }
        let exe = std::env::current_exe().expect("test binary path");
        let status = std::process::Command::new(exe)
            .arg("--exact")
            .arg("guard::tests::f01_abort_on_panic_guard_aborts_during_unwind")
            .arg("--nocapture")
            .env(MARKER, "1")
            .status()
            .expect("child process spawns");
        assert!(
            !status.success(),
            "a guard dropped during unwinding must abort the child, not return it"
        );
    }

    /// **The control.** Without the guard the same closure unwinds — which is
    /// what makes the guard's behaviour something it *provides* rather than
    /// something the runtime provides anyway.
    ///
    /// Written with an explicit `catch_unwind` in the test body rather than by
    /// calling a panicking closure bare: a test thread that panics fails the
    /// test, so the bare form would assert nothing and merely error. This form
    /// lets the assertion be "the unwind reached the boundary", which is the
    /// observable difference between having the guard and not.
    #[test]
    fn without_the_guard_the_panic_reaches_the_caller() {
        let reached = std::panic::catch_unwind(|| panic!("unguarded host bug"));
        assert!(
            reached.is_err(),
            "an unguarded closure must unwind; if this ever passes, the guard is \
             no longer doing anything and its tests are vacuous"
        );

        // And with the guard, the identical closure does not unwind.
        let guarded: wasmtime::Result<u32> = guard("f", || panic!("guarded host bug"));
        assert!(guarded.is_err(), "the guard must contain the same panic");
    }
}
