//! Linux process hardening — `SEC-019`.
//!
//! Implements Proposal §7.5:
//!
//! > | Host process | Dropped privileges, `no_new_privs`, minimal capabilities | Linux |
//! > | Syscalls | seccomp-BPF allowlist after startup | Linux |
//! >
//! > **Design rule:** none of these are *required* for QQQ's security claim. The
//! > capability engine is the boundary; these are depth. A host without seccomp is
//! > still safe against a malicious guest, and that is the property that makes QQQ
//! > deployable anywhere.
//!
//! # The design rule is load-bearing, and it shapes everything below
//!
//! *(none of these are required)* is not a hedge — it is the specification. It
//! means:
//!
//! 1. **Every step is optional and independently skippable.** A deployment that
//!    cannot drop privileges still runs.
//! 2. **A step that fails must be reportable, not fatal.** [`HardenReport`]
//!    returns what happened rather than an error, because "hardening was not
//!    applied" and "the host is broken" are different situations and conflating
//!    them makes an operator disable the whole thing.
//! 3. **Nothing here may be needed for correctness.** Every function is additive.
//!
//! # The `unsafe` question, answered rather than assumed
//!
//! `qqq-sys` is the crate §4.3 designates for `unsafe` OS primitives, and it
//! currently carries a bare `#![forbid(unsafe_code)]` because it is a stub. The
//! obvious way to implement this module would be `libc` calls inside `unsafe`
//! blocks — which would require the exception process to be triggered: a written
//! safety argument plus a **second maintainer**, and `SAFETY.md`'s ledger records
//! that no second maintainer exists (`GOV-008`, bus factor 1, risk `R-15`).
//!
//! **That requirement is bypassed rather than deferred, because safe wrappers
//! exist.** `nix` provides `setuid`, `setgid`, `setgroups` and
//! `set_no_new_privs` as safe functions, and `seccompiler` compiles a BPF program
//! from a typed filter description. Using them means:
//!
//! * this crate keeps `#![forbid(unsafe_code)]` — the architecture invariant holds;
//! * the exception process is not triggered, so nothing waits on `GOV-008`;
//! * the `unsafe` that *would* have been written here is instead maintained by
//!   crates whose whole purpose is to maintain it, under their own audits.
//!
//! The trade is a dependency rather than a block of `unsafe`, and it is the right
//! side of that trade: **an `unsafe` block we write is an obligation we hold
//! forever; a safe wrapper is an obligation the ecosystem holds and we review
//! once.**
//!
//! # What this module deliberately does NOT do
//!
//! * **Landlock LSM.** §7.5 lists it for defence in depth behind the capability
//!   engine, and it needs a newer kernel API than `nix` currently wraps safely.
//!   Named here rather than omitted silently.
//! * **Capability dropping (`capset`).** §7.5 names "minimal capabilities". A
//!   process that has already dropped to an unprivileged uid has no capabilities
//!   to drop, so for the common deployment this is subsumed — and doing it
//!   *instead* of dropping uid would be strictly weaker. Recorded rather than
//!   implemented, with the reasoning, so the gap is a decision and not an
//!   oversight.
//! * **seccomp on non-Linux.** The whole module compiles everywhere and does
//!   nothing off Linux, reporting [`Step::Unsupported`].

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

/// What happened to one hardening step.
///
/// # Why this is an enum and not a `bool`
///
/// `bool` would collapse three genuinely different outcomes, and the difference
/// matters to whoever reads a startup log:
///
/// | Variant | Means | Operator action |
/// |---|---|---|
/// | [`Step::Applied`] | the step ran and took effect | none |
/// | [`Step::Skipped`] | not requested, or nothing to do | none — this is normal |
/// | [`Step::Unsupported`] | this platform cannot do it | none on Linux; expected elsewhere |
/// | [`Step::Failed`] | requested, attempted, refused | **investigate** |
///
/// Only the last one is actionable, and a `bool` would make it indistinguishable
/// from the second — which is how a hardening deployment ends up quietly not
/// hardened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    /// The step ran and took effect.
    Applied,
    /// Not requested, or there was nothing to do.
    Skipped,
    /// The platform does not support this step.
    Unsupported,
    /// The step was requested and attempted, and the OS refused it.
    Failed,
}

impl Step {
    /// Whether this outcome needs attention.
    ///
    /// **`Unsupported` is deliberately not a failure.** §7.5's design rule says a
    /// host without seccomp is still safe; treating an unsupported step as a
    /// problem would make QQQ undeployable on macOS and Windows, which is the
    /// opposite of the "deployable anywhere" property the section claims.
    #[must_use]
    pub const fn is_problem(self) -> bool {
        matches!(self, Self::Failed)
    }

    /// A short machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Skipped => "skipped",
            Self::Unsupported => "unsupported",
            Self::Failed => "failed",
        }
    }
}

/// One named step and its outcome.
///
/// # Why this derives `Serialize` but NOT `Deserialize`
///
/// `step` is a `&'static str` — a step *name*, from the fixed set in
/// [`STEP_ORDER`]. `Deserialize` cannot produce a `&'static str` from input, so
/// the derive is not merely awkward here, it is **impossible**: the compiler
/// rejects it with *"lifetime `'de` must outlive `'static`"*, which is exactly
/// what happened when this type first carried both.
///
/// Making the field an owned `String` to satisfy the derive would be the wrong
/// fix. These names are a closed set defined in this module; a report that
/// *came from* JSON could name a step that does not exist, and every consumer
/// would then need to handle the unknown case — inventing an extensibility the
/// design does not have. A [`HardenReport`] is an **output**: the host produces
/// it and something reads it. It is never an input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StepOutcome {
    /// Which step, e.g. `no_new_privs`.
    pub step: &'static str,
    /// What happened.
    pub outcome: Step,
    /// Why, when that is not obvious.
    ///
    /// # Why this is always populated for `Failed` and `Unsupported`
    ///
    /// Because the operator's next action differs entirely between "seccomp is
    /// not available on this kernel" and "seccomp was refused because the filter
    /// was invalid". A bare `Failed` sends them to the wrong place.
    pub detail: Option<String>,
}

impl StepOutcome {
    /// A step that took effect.
    #[must_use]
    pub fn applied(step: &'static str) -> Self {
        Self {
            step,
            outcome: Step::Applied,
            detail: None,
        }
    }

    /// A step that was not needed, with the reason.
    #[must_use]
    pub fn skipped(step: &'static str, why: impl Into<String>) -> Self {
        Self {
            step,
            outcome: Step::Skipped,
            detail: Some(why.into()),
        }
    }

    /// A step this platform cannot do.
    #[must_use]
    pub fn unsupported(step: &'static str, why: impl Into<String>) -> Self {
        Self {
            step,
            outcome: Step::Unsupported,
            detail: Some(why.into()),
        }
    }

    /// A step that was refused.
    #[must_use]
    pub fn failed(step: &'static str, why: impl Into<String>) -> Self {
        Self {
            step,
            outcome: Step::Failed,
            detail: Some(why.into()),
        }
    }
}

/// The result of a hardening attempt.
///
/// # Why this is a value rather than a `Result`
///
/// Because hardening **never** fails the process. §7.5: none of it is required.
/// A `Result` would invite a caller to `?` on it, which would turn "this kernel
/// has no seccomp" into a startup failure — an availability bug introduced by a
/// defence-in-depth feature. The value carries the same information without
/// offering that mistake.
///
/// `Serialize` but not `Deserialize`, for the reason [`StepOutcome`] records: a
/// report is an output, and the step names are a closed set this module owns.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HardenReport {
    /// Every step, in the order it was attempted.
    pub steps: Vec<StepOutcome>,
}

impl HardenReport {
    /// An empty report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an outcome.
    pub fn push(&mut self, outcome: StepOutcome) {
        self.steps.push(outcome);
    }

    /// The outcome for a named step.
    #[must_use]
    pub fn get(&self, step: &str) -> Option<Step> {
        self.steps
            .iter()
            .find(|s| s.step == step)
            .map(|s| s.outcome)
    }

    /// Whether every step that was *attempted* succeeded.
    ///
    /// # Why this is not "all steps applied"
    ///
    /// Because a `Skipped` or `Unsupported` step is a correct outcome, not a
    /// shortfall. The question an operator asks is *"did anything go wrong?"*,
    /// which is exactly "was any step refused".
    #[must_use]
    pub fn is_clean(&self) -> bool {
        !self.steps.iter().any(|s| s.outcome.is_problem())
    }

    /// Every step that was refused, for a diagnostic.
    ///
    /// # Why an elided lifetime is enough here
    ///
    /// An earlier version named `'a` explicitly, carried over from a version of
    /// this type whose `Deserialize` derive made the elided form fail with
    /// *"lifetime `'de` must outlive `'static`"*. That error was in the **derive**,
    /// not in this signature, and naming the lifetime here never fixed it. Once
    /// the derive went (see [`StepOutcome`] for why it had to), the elided form
    /// became correct again and clippy's `needless_lifetimes` said so.
    ///
    /// Recorded because the original comment *justified* the explicit lifetime
    /// with reasoning that sounded right and was about the wrong thing — which is
    /// the kind of comment that outlives the fix and misleads the next reader.
    #[must_use]
    pub fn problems(&self) -> Vec<&StepOutcome> {
        self.steps
            .iter()
            .filter(|s| s.outcome.is_problem())
            .collect()
    }

    /// A one-line summary for a startup log.
    #[must_use]
    pub fn summary(&self) -> String {
        let applied = self
            .steps
            .iter()
            .filter(|s| s.outcome == Step::Applied)
            .count();
        let failed = self.problems().len();
        let total = self.steps.len();

        if failed == 0 {
            format!("{applied}/{total} hardening step(s) applied, none refused")
        } else {
            let names: Vec<&str> = self.problems().iter().map(|s| s.step).collect();
            format!(
                "{applied}/{total} hardening step(s) applied; REFUSED: {}",
                names.join(", ")
            )
        }
    }
}

// ---------------------------------------------------------------------------
// The policy
// ---------------------------------------------------------------------------

/// What the caller wants hardened.
///
/// # Why every field is opt-out rather than opt-in
///
/// Defaults are the *hardened* choice, because a deployment that forgets to
/// configure hardening should get it, not miss it. The exceptions are the two
/// that cannot be defaulted safely:
///
/// * **Dropping privileges** changes the process's identity irreversibly, so it
///   needs an explicit target uid rather than a guessed one.
/// * **seccomp** can kill a process whose workload uses a syscall the filter did
///   not anticipate, so it needs an explicit opt-in with a named profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardenPolicy {
    /// Install a seccomp-BPF filter.
    ///
    /// **Off by default**, and the reason is availability rather than security: a
    /// filter that omits a syscall the guest runtime needs turns a working
    /// deployment into a crashing one. §7.5 says seccomp is depth, and depth that
    /// breaks the service is worse than depth that is absent.
    pub seccomp: bool,
    /// Which syscall profile to install, when `seccomp` is set.
    pub seccomp_profile: SeccompProfile,
    /// Drop to this uid, when set.
    ///
    /// `None` means "do not drop", which is correct when the process was started
    /// as an unprivileged user already — the common case under a container
    /// runtime, and the one where attempting `setuid` would *fail* and produce a
    /// spurious `Failed` entry.
    pub drop_to_uid: Option<u32>,
    /// Drop to this gid, when set.
    pub drop_to_gid: Option<u32>,
}

impl Default for HardenPolicy {
    /// The safe defaults: `no_new_privs` on, seccomp off, no identity change.
    fn default() -> Self {
        Self {
            seccomp: false,
            seccomp_profile: SeccompProfile::Runtime,
            drop_to_uid: None,
            drop_to_gid: None,
        }
    }
}

/// Which syscall allowlist to install.
///
/// # Why a named profile rather than a list of syscalls
///
/// A syscall list in a config file is a security policy nobody can review: the
/// reader cannot tell whether `io_uring_setup` belongs, and the answer depends on
/// which reactor the deployment uses. Named profiles are reviewed **once**, in
/// this file, with the reasoning beside them — and an unknown name is refused
/// rather than treated as "allow everything", which is the failure mode a
/// free-form list invites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompProfile {
    /// The syscalls the QQQ host itself needs after startup.
    ///
    /// Deliberately permissive about I/O and threading, because a false negative
    /// here is a production outage: the filter is a **backstop** against a
    /// compromised *host*, not the guest boundary (§7.5's design rule). The guest
    /// boundary is the capability engine.
    Runtime,
}

impl SeccompProfile {
    /// The syscalls this profile permits.
    ///
    /// # How this list was chosen, and what it is not
    ///
    /// It is the set a Tokio-based host needs to accept connections, run the
    /// epoch ticker, write logs and shut down cleanly — enumerated from what the
    /// runtime actually calls rather than copied from a hardening guide, because
    /// a copied list is a list whose omissions nobody can reason about.
    ///
    /// **It is intentionally not minimal.** A minimal list would refuse a syscall
    /// the allocator uses on a different glibc version and kill the process; the
    /// value of the profile is that it excludes the *families* a compromised host
    /// would use to escalate (`ptrace`, `mount`, `kexec_*`, `bpf`,
    /// `process_vm_*`, `init_module`, `setuid` after startup), not that it is the
    /// smallest set that works.
    /// Every syscall the [`SeccompProfile::Runtime`] profile permits.
    ///
    /// An **associated** constant, because the list is a property of the profile
    /// rather than a free-standing table: `Self::RUNTIME_ALLOWLIST` reads as what
    /// it is, and a second profile added later gets its own.
    ///
    /// # Why this is a constant rather than a `match` arm
    ///
    /// clippy's `too_many_lines` flagged the function that used to hold this
    /// inline, and the lint was pointing at something real: a 130-entry array
    /// inside a `match` arm reads as an undifferentiated list, whereas a named
    /// constant states *what the list is* at the point of use and gives a test a
    /// name to assert against.
    ///
    /// The `// --` banners below are the actual reviewable unit. Each names a
    /// group whose membership a reviewer can check as a claim about the runtime
    /// ("a server needs these socket calls") rather than as an entry to skim.
    const RUNTIME_ALLOWLIST: &[&str] = &[
        // -- process and thread lifecycle -------------------------
        "exit",
        "exit_group",
        "clone",
        "clone3",
        "futex",
        "set_robust_list",
        "get_robust_list",
        "rseq",
        "sched_yield",
        "sched_getaffinity",
        "set_tid_address",
        "gettid",
        "getpid",
        "getppid",
        "tgkill",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "rt_sigtimedwait",
        "sigaltstack",
        "restart_syscall",
        "prctl",
        "arch_prctl",
        // -- memory ------------------------------------------------
        "brk",
        "mmap",
        "munmap",
        "mremap",
        "madvise",
        "mprotect",
        "memfd_create",
        // -- file descriptors and I/O ------------------------------
        "read",
        "write",
        "readv",
        "writev",
        "pread64",
        "pwrite64",
        "close",
        "close_range",
        "dup",
        "dup2",
        "dup3",
        "fcntl",
        "ioctl",
        "lseek",
        "pipe",
        "pipe2",
        "eventfd",
        "eventfd2",
        "epoll_create",
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
        "epoll_pwait",
        "epoll_pwait2",
        "poll",
        "ppoll",
        "select",
        "pselect6",
        // -- sockets ----------------------------------------------
        "socket",
        "socketpair",
        "bind",
        "listen",
        "accept",
        "accept4",
        "connect",
        "shutdown",
        "sendto",
        "recvfrom",
        "sendmsg",
        "recvmsg",
        "sendmmsg",
        "recvmmsg",
        "getsockname",
        "getpeername",
        "getsockopt",
        "setsockopt",
        // -- time -------------------------------------------------
        "clock_gettime",
        "clock_nanosleep",
        "nanosleep",
        "gettimeofday",
        "timerfd_create",
        "timerfd_settime",
        "timerfd_gettime",
        // -- filesystem (read-mostly; grants decide access) --------
        "openat",
        "openat2",
        "stat",
        "statx",
        "lstat",
        "fstat",
        "fstatfs",
        "statfs",
        "newfstatat",
        "access",
        "faccessat",
        "faccessat2",
        "getdents64",
        "readlink",
        "readlinkat",
        "getcwd",
        "chdir",
        "fchdir",
        "rename",
        "renameat",
        "renameat2",
        "unlink",
        "unlinkat",
        "mkdir",
        "mkdirat",
        "rmdir",
        "fsync",
        "fdatasync",
        "ftruncate",
        "truncate",
        "fallocate",
        "copy_file_range",
        "sendfile",
        "splice",
        // -- entropy and identity ----------------------------------
        "getrandom",
        "getuid",
        "geteuid",
        "getgid",
        "getegid",
        "getgroups",
        "uname",
        "sysinfo",
        // -- io_uring (PERF-014's reactor) --------------------------
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
    ];

    /// The syscalls this profile permits.
    ///
    /// Returns [`Self::RUNTIME_ALLOWLIST`]; see that constant for the list and the
    /// reasoning behind each group.
    #[must_use]
    pub const fn allowed(self) -> &'static [&'static str] {
        match self {
            Self::Runtime => Self::RUNTIME_ALLOWLIST,
        }
    }

    /// Syscalls the profile deliberately refuses, named so the refusal is a
    /// decision a reviewer can check.
    ///
    /// # Why an explicit deny list when the model is allow-by-default
    ///
    /// Because the *reason* each is excluded is the part worth recording, and a
    /// reader comparing this profile against a kernel's syscall table needs to
    /// know which omissions were deliberate. Every entry here is a syscall that
    /// would let a compromised host escalate, inspect another process, or load
    /// code — none of which a running QQQ host legitimately needs.
    #[must_use]
    pub const fn denied(self) -> &'static [&'static str] {
        match self {
            Self::Runtime => &[
                // Debugging and cross-process memory access.
                "ptrace",
                "process_vm_readv",
                "process_vm_writev",
                // Kernel and module manipulation.
                "init_module",
                "finit_module",
                "delete_module",
                "kexec_load",
                "kexec_file_load",
                "reboot",
                // Attaching BPF programs, and the syscall used to build exploits.
                "bpf",
                "userfaultfd",
                // Mounting, and the namespaces that would allow escaping a jail.
                "mount",
                "umount2",
                "pivot_root",
                "chroot",
                "unshare",
                "setns",
                // Identity changes after startup: hardening that can be undone is
                // not hardening.
                "setuid",
                "setgid",
                "setreuid",
                "setregid",
                "setresuid",
                "setresgid",
                "setgroups",
                // Kernel keyring and performance counters.
                "add_key",
                "request_key",
                "keyctl",
                "perf_event_open",
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// The steps
// ---------------------------------------------------------------------------

/// Step name: set `PR_SET_NO_NEW_PRIVS`.
pub const STEP_NO_NEW_PRIVS: &str = "no_new_privs";
/// Step name: drop the group identity.
pub const STEP_DROP_GID: &str = "drop_privileges_gid";
/// Step name: drop the user identity.
pub const STEP_DROP_UID: &str = "drop_privileges_uid";
/// Step name: install the seccomp-BPF filter.
pub const STEP_SECCOMP: &str = "seccomp";

/// Every step name, in the order [`harden`] attempts them.
///
/// # Why the order is fixed and documented
///
/// Each step strictly depends on the one before it:
///
/// | # | Step | Why it must come here |
/// |---|---|---|
/// | 1 | `no_new_privs` | must precede seccomp: a filter can only be installed under `no_new_privs` without `CAP_SYS_ADMIN` |
/// | 2 | `drop_privileges_gid` | groups must be dropped before the uid, because dropping the uid removes the authority to call `setgroups` |
/// | 3 | `drop_privileges_uid` | after the gid, and irreversible |
/// | 4 | `seccomp` | last: the filter refuses `setuid`/`setgid`, so it must come after any identity change |
///
/// The order is a **security** property, not a style: reversing steps 2 and 3
/// makes the gid drop fail, and putting seccomp first makes the uid drop die with
/// `SIGSYS`. Both are silent-looking failures — the process keeps running, merely
/// less hardened — which is why this table exists in the code rather than only in
/// a commit message.
pub const STEP_ORDER: &[&str] = &[
    STEP_NO_NEW_PRIVS,
    STEP_DROP_GID,
    STEP_DROP_UID,
    STEP_SECCOMP,
];

/// Apply the hardening steps in [`STEP_ORDER`].
///
/// # Never fails
///
/// Returns a [`HardenReport`] describing what happened. See that type for why
/// this is not a `Result`.
///
/// # The steps, and what each defends against
///
/// * **`no_new_privs`** — a `setuid` binary executed by this process cannot gain
///   privilege. Without it, a compromise that reaches `execve` can re-escalate
///   through any setuid binary on the filesystem.
/// * **Dropping gid then uid** — the process loses the authority to read or write
///   anything the target identity cannot. This is the step that bounds the blast
///   radius of a compromise that escapes Wasm entirely: §7.1's first asset is
///   *host process integrity*, and this is what makes its loss less than total.
/// * **seccomp** — narrows the syscall surface a compromised host can reach. It is
///   the weakest of the three (a filter is a policy, not a boundary) and the
///   reason it is off by default.
#[must_use]
pub fn harden(policy: &HardenPolicy) -> HardenReport {
    let mut report = HardenReport::new();

    report.push(apply_no_new_privs());
    report.push(apply_drop_gid(policy));
    report.push(apply_drop_uid(policy));
    report.push(apply_seccomp(policy));

    report
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod imp {
    use super::{
        HardenPolicy, SeccompProfile, StepOutcome, STEP_DROP_GID, STEP_DROP_UID, STEP_NO_NEW_PRIVS,
        STEP_SECCOMP,
    };
    use nix::unistd::{Gid, Uid};

    /// Set `PR_SET_NO_NEW_PRIVS`.
    pub(super) fn no_new_privs() -> StepOutcome {
        // Always applied on Linux: there is no configuration under which a QQQ
        // host benefits from allowing a setuid binary to grant it privilege, and
        // making it optional would only add a way to be less safe by omission.
        match nix::sys::prctl::set_no_new_privs() {
            Ok(()) => StepOutcome::applied(STEP_NO_NEW_PRIVS),
            Err(e) => StepOutcome::failed(
                STEP_NO_NEW_PRIVS,
                format!("prctl(PR_SET_NO_NEW_PRIVS) was refused by the kernel: {e}"),
            ),
        }
    }

    /// Drop the group identity.
    pub(super) fn drop_gid(policy: &HardenPolicy) -> StepOutcome {
        let Some(gid) = policy.drop_to_gid else {
            return StepOutcome::skipped(
                STEP_DROP_GID,
                "no `drop_to_gid` was configured, so the process keeps the groups it \
                 was started with",
            );
        };

        // Supplementary groups FIRST, and this is the step that is easy to miss.
        // `setgid` changes the *primary* group only; a process started by root
        // keeps root's supplementary groups, and those are checked by the kernel
        // on file access just as the primary is. Dropping the primary group and
        // leaving the supplementary ones is a hardening step that reads as
        // complete and is not.
        if let Err(e) = nix::unistd::setgroups(&[Gid::from_raw(gid)]) {
            return StepOutcome::failed(
                STEP_DROP_GID,
                format!(
                    "setgroups was refused: {e}; the supplementary groups are still \
                         those of the starting user, which is a partial drop"
                ),
            );
        }

        match nix::unistd::setgid(Gid::from_raw(gid)) {
            Ok(()) => StepOutcome::applied(STEP_DROP_GID),
            Err(e) => StepOutcome::failed(STEP_DROP_GID, format!("setgid was refused: {e}")),
        }
    }

    /// Drop the user identity.
    pub(super) fn drop_uid(policy: &HardenPolicy) -> StepOutcome {
        let Some(uid) = policy.drop_to_uid else {
            return StepOutcome::skipped(
                STEP_DROP_UID,
                "no `drop_to_uid` was configured, so the process keeps the uid it was \
                 started with",
            );
        };

        // Refuse to drop to root. `setuid(0)` when already root is a no-op that
        // reports success, so a policy that named uid 0 would produce an
        // `Applied` entry for a step that did nothing — the exact shape of a
        // hardening report that lies.
        if uid == 0 {
            return StepOutcome::failed(
                STEP_DROP_UID,
                "`drop_to_uid` is 0, which is root; dropping to root is a no-op that \
                 would be reported as applied",
            );
        }

        match nix::unistd::setuid(Uid::from_raw(uid)) {
            Ok(()) => StepOutcome::applied(STEP_DROP_UID),
            Err(e) => StepOutcome::failed(STEP_DROP_UID, format!("setuid was refused: {e}")),
        }
    }

    /// Install the seccomp-BPF filter.
    pub(super) fn seccomp(policy: &HardenPolicy) -> StepOutcome {
        if !policy.seccomp {
            return StepOutcome::skipped(
                STEP_SECCOMP,
                "seccomp was not requested; §7.5 treats it as defence in depth rather \
                 than as the guest boundary",
            );
        }

        let profile = policy.seccomp_profile;
        match build_and_install(profile) {
            Ok(()) => StepOutcome::applied(STEP_SECCOMP),
            Err(detail) => StepOutcome::failed(STEP_SECCOMP, detail),
        }
    }

    /// The action taken for a syscall the profile does **not** list.
    ///
    /// # The defect this function exists to make testable — found by the Linux bridge
    ///
    /// The first version of this code passed `SeccompAction::Errno(EPERM)` inline as
    /// the filter's default action, and `seccomp_applies_in_a_child` asserted only
    /// that the filter was **installed**. Those two facts together meant the
    /// following patch passed every test in the workspace:
    ///
    /// ```diff
    /// -            SeccompAction::Errno(libc::EPERM as u32),
    /// +            SeccompAction::Allow,
    /// ```
    ///
    /// That turns the filter into a **default-allow** program: every syscall not on
    /// the allowlist is permitted, which is exactly the seccomp bypass the profile
    /// was written to prevent. A default-allow filter is *still installed*, so
    /// "installation succeeded" was true — and the guard's whole purpose was
    /// unverified.
    ///
    /// **Nothing on Windows could have found this.** The code is
    /// `#[cfg(target_os = "linux")]`, so the test was compiled out, and the
    /// injection was unexercised. It took a Linux environment to make the
    /// injection fire at all — `§O-085`.
    ///
    /// # Why a named function rather than an inline constant
    ///
    /// So a test has a **seam**. Asserting on this function's return value is what
    /// makes the guard reachable: a test can now fail if the default action ever
    /// stops being a refusal, without needing to trap a signal in a child process.
    /// The two mechanisms are complementary — this proves the *policy*, and
    /// [`install_and_probe`] proves the kernel enforces it.
    #[must_use]
    fn deny_action() -> seccompiler::SeccompAction {
        // `EPERM` rather than `KillProcess`. Both refuse, and the difference is
        // what the guest sees: a killed process is indistinguishable from a crash
        // (and would surface as an unexplained `SIGSYS` in a log), whereas `EPERM`
        // reaches the guest as a normal error it can handle and report. A
        // backstop should degrade a request, not terminate the host.
        seccompiler::SeccompAction::Errno(libc::EPERM as u32)
    }

    /// Compile the profile and install it.
    ///
    /// # Why the filter is a *default-deny* program
    ///
    /// A filter that listed denied syscalls and permitted everything else would
    /// be defeated by any syscall newer than the list — which is the whole
    /// history of seccomp bypasses. The program denies by default and permits an
    /// explicit allowlist, so a syscall added to Linux tomorrow is refused without
    /// anyone updating this file.
    fn build_and_install(profile: SeccompProfile) -> Result<(), String> {
        use seccompiler::{SeccompAction, SeccompFilter};

        let arch = seccompiler::TargetArch::try_from(std::env::consts::ARCH)
            .map_err(|e| format!("no seccomp target arch for this platform: {e}"))?;

        // A `BTreeMap<i64, Vec<SeccompRule>>` of syscall number to rules. An empty
        // rule vector means "permit unconditionally", which is what every entry
        // here is: this profile filters by *which* syscall, not by its arguments.
        //
        // Argument filtering is a real technique and is deliberately not used:
        // a rule on `openat`'s flags would have to be re-derived per kernel
        // version, and a wrong rule refuses a legitimate call — an outage caused
        // by a hardening feature.
        let mut rules = std::collections::BTreeMap::new();
        for name in profile.allowed() {
            let Some(nr) = syscall_number(name) else {
                return Err(format!(
                    "the `Runtime` profile names `{name}`, which this architecture does \
                     not have; the profile is platform-specific and this is a QQQ bug \
                     rather than a configuration error"
                ));
            };
            rules.insert(i64::from(nr), Vec::new());
        }

        let filter = SeccompFilter::new(
            rules,
            // Default-deny: anything not listed is refused, with `EPERM` so a guest
            // sees "operation not permitted" rather than a signal. See
            // [`SeccompProfile::denied`] for why this direction is the one that
            // matters.
            deny_action(),
            // Matched syscalls are permitted.
            SeccompAction::Allow,
            arch,
        )
        .map_err(|e| format!("the seccomp filter was rejected at construction: {e}"))?;

        let program: seccompiler::BpfProgram = filter
            .try_into()
            .map_err(|e| format!("the seccomp filter failed to compile to BPF: {e}"))?;

        seccompiler::apply_filter(&program)
            .map_err(|e| format!("the kernel refused the seccomp filter: {e}"))
    }

    /// Resolve a syscall name to its number on this architecture.
    ///
    /// # Why the names are resolved here rather than hard-coded
    ///
    /// Syscall numbers differ between x86-64 and aarch64, so a list of numbers
    /// would be correct on one architecture and catastrophic on the other —
    /// refusing every legitimate call. Resolving by name at runtime means the
    /// profile is written once, in portable terms, and each architecture gets its
    /// own numbers.
    fn syscall_number(name: &str) -> Option<i64> {
        use std::collections::HashMap;
        use std::sync::OnceLock;

        // Built once from `libc`'s constants, which are the authoritative
        // architecture-specific values.
        static TABLE: OnceLock<HashMap<&'static str, i64>> = OnceLock::new();

        let table = TABLE.get_or_init(|| {
            // `libc::SYS_*` are `c_long` and differ per architecture; taking them
            // through this table is what keeps the profile portable.
            let mut m = HashMap::new();
            macro_rules! syscalls {
                ($($name:literal => $const:expr),* $(,)?) => {
                    $( m.insert($name, i64::from($const)); )*
                };
            }
            syscalls! {
                "exit" => libc::SYS_exit,
                "exit_group" => libc::SYS_exit_group,
                "clone" => libc::SYS_clone,
                "futex" => libc::SYS_futex,
                "sched_yield" => libc::SYS_sched_yield,
                "gettid" => libc::SYS_gettid,
                "getpid" => libc::SYS_getpid,
                "getppid" => libc::SYS_getppid,
                "tgkill" => libc::SYS_tgkill,
                "rt_sigaction" => libc::SYS_rt_sigaction,
                "rt_sigprocmask" => libc::SYS_rt_sigprocmask,
                "rt_sigreturn" => libc::SYS_rt_sigreturn,
                "sigaltstack" => libc::SYS_sigaltstack,
                "prctl" => libc::SYS_prctl,
                "brk" => libc::SYS_brk,
                "mmap" => libc::SYS_mmap,
                "munmap" => libc::SYS_munmap,
                "mremap" => libc::SYS_mremap,
                "madvise" => libc::SYS_madvise,
                "mprotect" => libc::SYS_mprotect,
                "read" => libc::SYS_read,
                "write" => libc::SYS_write,
                "readv" => libc::SYS_readv,
                "writev" => libc::SYS_writev,
                "pread64" => libc::SYS_pread64,
                "pwrite64" => libc::SYS_pwrite64,
                "close" => libc::SYS_close,
                "dup" => libc::SYS_dup,
                "dup2" => libc::SYS_dup2,
                "dup3" => libc::SYS_dup3,
                "fcntl" => libc::SYS_fcntl,
                "ioctl" => libc::SYS_ioctl,
                "lseek" => libc::SYS_lseek,
                "pipe" => libc::SYS_pipe,
                "pipe2" => libc::SYS_pipe2,
                "eventfd" => libc::SYS_eventfd,
                "eventfd2" => libc::SYS_eventfd2,
                "epoll_create" => libc::SYS_epoll_create,
                "epoll_create1" => libc::SYS_epoll_create1,
                "epoll_ctl" => libc::SYS_epoll_ctl,
                "epoll_wait" => libc::SYS_epoll_wait,
                "epoll_pwait" => libc::SYS_epoll_pwait,
                "poll" => libc::SYS_poll,
                "ppoll" => libc::SYS_ppoll,
                "select" => libc::SYS_select,
                "pselect6" => libc::SYS_pselect6,
                "socket" => libc::SYS_socket,
                "socketpair" => libc::SYS_socketpair,
                "bind" => libc::SYS_bind,
                "listen" => libc::SYS_listen,
                "accept" => libc::SYS_accept,
                "accept4" => libc::SYS_accept4,
                "connect" => libc::SYS_connect,
                "shutdown" => libc::SYS_shutdown,
                "sendto" => libc::SYS_sendto,
                "recvfrom" => libc::SYS_recvfrom,
                "sendmsg" => libc::SYS_sendmsg,
                "recvmsg" => libc::SYS_recvmsg,
                "getsockname" => libc::SYS_getsockname,
                "getpeername" => libc::SYS_getpeername,
                "getsockopt" => libc::SYS_getsockopt,
                "setsockopt" => libc::SYS_setsockopt,
                "clock_gettime" => libc::SYS_clock_gettime,
                "clock_nanosleep" => libc::SYS_clock_nanosleep,
                "nanosleep" => libc::SYS_nanosleep,
                "gettimeofday" => libc::SYS_gettimeofday,
                "timerfd_create" => libc::SYS_timerfd_create,
                "timerfd_settime" => libc::SYS_timerfd_settime,
                "timerfd_gettime" => libc::SYS_timerfd_gettime,
                "openat" => libc::SYS_openat,
                "stat" => libc::SYS_stat,
                "statx" => libc::SYS_statx,
                "lstat" => libc::SYS_lstat,
                "fstat" => libc::SYS_fstat,
                "fstatfs" => libc::SYS_fstatfs,
                "statfs" => libc::SYS_statfs,
                "newfstatat" => libc::SYS_newfstatat,
                "access" => libc::SYS_access,
                "faccessat" => libc::SYS_faccessat,
                "getdents64" => libc::SYS_getdents64,
                "readlink" => libc::SYS_readlink,
                "readlinkat" => libc::SYS_readlinkat,
                "getcwd" => libc::SYS_getcwd,
                "chdir" => libc::SYS_chdir,
                "fchdir" => libc::SYS_fchdir,
                "rename" => libc::SYS_rename,
                "renameat" => libc::SYS_renameat,
                "unlink" => libc::SYS_unlink,
                "unlinkat" => libc::SYS_unlinkat,
                "mkdir" => libc::SYS_mkdir,
                "mkdirat" => libc::SYS_mkdirat,
                "rmdir" => libc::SYS_rmdir,
                "fsync" => libc::SYS_fsync,
                "fdatasync" => libc::SYS_fdatasync,
                "ftruncate" => libc::SYS_ftruncate,
                "truncate" => libc::SYS_truncate,
                "fallocate" => libc::SYS_fallocate,
                "sendfile" => libc::SYS_sendfile,
                "splice" => libc::SYS_splice,
                "getrandom" => libc::SYS_getrandom,
                "getuid" => libc::SYS_getuid,
                "geteuid" => libc::SYS_geteuid,
                "getgid" => libc::SYS_getgid,
                "getegid" => libc::SYS_getegid,
                "getgroups" => libc::SYS_getgroups,
                "uname" => libc::SYS_uname,
                "sysinfo" => libc::SYS_sysinfo,
            }
            // Architecture-specific optional entries, added only where they exist.
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            {
                m.insert("clone3", i64::from(libc::SYS_clone3));
                m.insert("rseq", i64::from(libc::SYS_rseq));
                m.insert("set_robust_list", i64::from(libc::SYS_set_robust_list));
                m.insert("get_robust_list", i64::from(libc::SYS_get_robust_list));
                m.insert("sched_getaffinity", i64::from(libc::SYS_sched_getaffinity));
                m.insert("set_tid_address", i64::from(libc::SYS_set_tid_address));
                m.insert("rt_sigtimedwait", i64::from(libc::SYS_rt_sigtimedwait));
                m.insert("restart_syscall", i64::from(libc::SYS_restart_syscall));
                m.insert("arch_prctl", i64::from(libc::SYS_arch_prctl));
                m.insert("memfd_create", i64::from(libc::SYS_memfd_create));
                m.insert("close_range", i64::from(libc::SYS_close_range));
                m.insert("epoll_pwait2", i64::from(libc::SYS_epoll_pwait2));
                m.insert("sendmmsg", i64::from(libc::SYS_sendmmsg));
                m.insert("recvmmsg", i64::from(libc::SYS_recvmmsg));
                m.insert("openat2", i64::from(libc::SYS_openat2));
                m.insert("faccessat2", i64::from(libc::SYS_faccessat2));
                m.insert("renameat2", i64::from(libc::SYS_renameat2));
                m.insert("copy_file_range", i64::from(libc::SYS_copy_file_range));
                m.insert("io_uring_setup", i64::from(libc::SYS_io_uring_setup));
                m.insert("io_uring_enter", i64::from(libc::SYS_io_uring_enter));
                m.insert("io_uring_register", i64::from(libc::SYS_io_uring_register));
            }
            m
        });

        table.get(name).copied()
    }
}

// ---------------------------------------------------------------------------
// Non-Linux implementation
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::{
        HardenPolicy, StepOutcome, STEP_DROP_GID, STEP_DROP_UID, STEP_NO_NEW_PRIVS, STEP_SECCOMP,
    };

    /// `no_new_privs` is a Linux `prctl`, so there is nothing to do elsewhere.
    pub(super) fn no_new_privs() -> StepOutcome {
        StepOutcome::unsupported(
            STEP_NO_NEW_PRIVS,
            "PR_SET_NO_NEW_PRIVS is a Linux prctl; §7.5 lists the host-process \
             hardening steps as Linux-only",
        )
    }

    pub(super) fn drop_gid(_policy: &HardenPolicy) -> StepOutcome {
        StepOutcome::unsupported(
            STEP_DROP_GID,
            "privilege dropping is implemented for Linux; on other platforms the \
             process identity is managed by the platform's own mechanism",
        )
    }

    pub(super) fn drop_uid(_policy: &HardenPolicy) -> StepOutcome {
        StepOutcome::unsupported(
            STEP_DROP_UID,
            "privilege dropping is implemented for Linux; see the step above",
        )
    }

    pub(super) fn seccomp(_policy: &HardenPolicy) -> StepOutcome {
        StepOutcome::unsupported(
            STEP_SECCOMP,
            "seccomp-BPF is a Linux facility; other platforms have their own sandbox \
             mechanisms and §7.5's design rule means their absence is not a defect",
        )
    }
}

// Thin wrappers so the public `harden` reads the same on both platforms.
#[cfg(target_os = "linux")]
fn apply_no_new_privs() -> StepOutcome {
    imp::no_new_privs()
}
#[cfg(target_os = "linux")]
fn apply_drop_gid(policy: &HardenPolicy) -> StepOutcome {
    imp::drop_gid(policy)
}
#[cfg(target_os = "linux")]
fn apply_drop_uid(policy: &HardenPolicy) -> StepOutcome {
    imp::drop_uid(policy)
}
#[cfg(target_os = "linux")]
fn apply_seccomp(policy: &HardenPolicy) -> StepOutcome {
    imp::seccomp(policy)
}

#[cfg(not(target_os = "linux"))]
fn apply_no_new_privs() -> StepOutcome {
    imp::no_new_privs()
}
#[cfg(not(target_os = "linux"))]
fn apply_drop_gid(policy: &HardenPolicy) -> StepOutcome {
    imp::drop_gid(policy)
}
#[cfg(not(target_os = "linux"))]
fn apply_drop_uid(policy: &HardenPolicy) -> StepOutcome {
    imp::drop_uid(policy)
}
#[cfg(not(target_os = "linux"))]
fn apply_seccomp(policy: &HardenPolicy) -> StepOutcome {
    imp::seccomp(policy)
}
