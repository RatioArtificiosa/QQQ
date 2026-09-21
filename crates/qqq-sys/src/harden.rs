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
//! * **Landlock LSM** — implemented since `SEC-026`; see [`STEP_LANDLOCK`]. The
//!   note that used to appear here said the feature "needs a newer kernel API than
//!   `nix` currently wraps safely", which was true of `nix` and false as a
//!   *conclusion*: the `landlock` crate wraps it safely.
//! * **Enforcing MPK.** `SEC-027` is **detected** here ([`mpk_support`]) and not
//!   enforced, for a hard reason rather than a preference — every available crate
//!   is a thin `unsafe` FFI wrapper, and this crate may not contain `unsafe` until
//!   `SAFETY.md`'s ledger changes, which needs a second maintainer (`GOV-008`).
//!   The detection is still worth having: it turns "MPK is unavailable" from a
//!   guess into a measurement, and it is what a deployment that *does* have the
//!   hardware needs in order to know that enforcement is the next step rather than
//!   an unknown.
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

    /// A step that took effect, with a note about *how far* it went.
    ///
    /// # Why "applied" sometimes needs detail
    ///
    /// Landlock's ABI is negotiated: a kernel may enforce fewer access rights than
    /// the source requested, and the ruleset still installs. Reporting a bare
    /// `Applied` would hide which ABI was actually in force, and the difference
    /// matters — a ruleset enforced at ABI v1 does not cover `REFER` or `TRUNCATE`,
    /// so an operator reading "applied" would believe more is restricted than is.
    #[must_use]
    pub fn applied_with(step: &'static str, detail: impl Into<String>) -> Self {
        Self {
            step,
            outcome: Step::Applied,
            detail: Some(detail.into()),
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
    /// Install a Landlock filesystem ruleset (`SEC-026`).
    ///
    /// **Off by default**, for the same reason as `seccomp` and a stronger version
    /// of it: Landlock is *irreversible* for the process that installs it. A
    /// ruleset that omits a path the host later needs cannot be widened, so the
    /// process must be restarted — which means a wrong ruleset is an outage, not a
    /// degraded mode.
    pub landlock: bool,
    /// Which paths to keep accessible, when `landlock` is set.
    ///
    /// # Why this is empty by default, and why empty means "nothing"
    ///
    /// A Landlock ruleset with no rules denies **every** filesystem access the
    /// handled rights cover. That is the correct secure default and an almost
    /// certainly fatal one, which is why `landlock` is off unless a caller has
    /// thought about which paths to grant.
    ///
    /// The field holds directories, and a rule on a directory applies to the whole
    /// subtree beneath it. A path that does not exist is reported as `Failed`
    /// rather than skipped: silently ignoring a typo'd path produces a process that
    /// runs with fewer filesystem rights than its operator intended, and the
    /// symptom would be a permission error somewhere unrelated.
    pub landlock_read_paths: Vec<std::path::PathBuf>,
}

impl Default for HardenPolicy {
    /// The safe defaults: `no_new_privs` on, seccomp and Landlock off, no identity
    /// change.
    fn default() -> Self {
        Self {
            seccomp: false,
            seccomp_profile: SeccompProfile::Runtime,
            drop_to_uid: None,
            drop_to_gid: None,
            landlock: false,
            landlock_read_paths: Vec::new(),
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
/// Step name: install the Landlock filesystem ruleset.
pub const STEP_LANDLOCK: &str = "landlock";
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
/// | 4 | `landlock` | after the identity change, before seccomp — see below |
/// | 5 | `seccomp` | last: the filter refuses `setuid`/`setgid` and the `landlock_*` syscalls, so it must come after both |
///
/// The order is a **security** property, not a style: reversing steps 2 and 3
/// makes the gid drop fail, and putting seccomp first makes the uid drop die with
/// `SIGSYS`. Both are silent-looking failures — the process keeps running, merely
/// less hardened — which is why this table exists in the code rather than only in
/// a commit message.
///
/// # Why Landlock sits between the uid drop and seccomp
///
/// * **After the uid drop**, because Landlock is designed for unprivileged
///   processes and becomes *more* meaningful once the process no longer holds
///   `CAP_SYS_ADMIN`: a Landlock ruleset is not enforced against a process with
///   that capability, so restricting before dropping would produce a sandbox that
///   silently does not bind. This is the ordering mistake that would look correct
///   and be inert.
/// * **Before seccomp**, because the `landlock_create_ruleset`,
///   `landlock_add_rule` and `landlock_restrict_self` syscalls must still be
///   permitted when the filter installs. Installing seccomp first would make the
///   Landlock step fail with a `SIGSYS` kill or an `EPERM`, and the failure would
///   be reported as "the kernel refused Landlock" — pointing at the wrong thing.
pub const STEP_ORDER: &[&str] = &[
    STEP_NO_NEW_PRIVS,
    STEP_DROP_GID,
    STEP_DROP_UID,
    STEP_LANDLOCK,
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
///
/// What the running host supports of §7.5's optional hardening.
///
/// # Why detection exists when enforcement does not
///
/// `SEC-027` asks for memory-protection-key support. Enforcement is blocked — see
/// [`mpk_support`] for the exact reason — but detection is not, and it is worth
/// having on its own for three reasons.
///
/// It turns "MPK is unavailable" from an assumption into a measurement, so a
/// deployment can say why it runs without MPK and an operator with the hardware
/// knows the gap is software rather than silicon. It is the piece `SEC-027` needs
/// first regardless, since enforcing MPK without detecting it produces `SIGSEGV` on
/// hardware that lacks `pku` — a crash rather than a hardening step. And it is
/// honest: a module that lists a capability as "deliberately not done" without
/// saying whether the machine *could* do it leaves a reader unable to tell a policy
/// decision from an environment limit.
///
/// # Why this is not a `HardenPolicy` field
///
/// A policy is what the operator *asks for*; this is what the *host offers*. Putting
/// it in the policy would let a caller assert a hardware fact, and the assertion
/// would be indistinguishable from a measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCapabilities {
    /// Whether the CPU advertises Memory Protection Keys (`pku` on x86-64,
    /// equivalent feature bits elsewhere).
    ///
    /// Read from `HWCAP`/`/proc/cpuinfo` rather than attempted, because attempting
    /// an MPK operation on hardware without it faults rather than returning an
    /// error.
    pub memory_protection_keys: bool,
    /// Whether Landlock is available on this kernel.
    ///
    /// Reported separately from the [`STEP_LANDLOCK`] outcome because the outcome
    /// depends on whether a caller *requested* it, and "the kernel has it" is the
    /// fact an operator needs when deciding whether to ask.
    pub landlock: bool,
}

/// Detect whether the host has MPK, and why enforcement is not wired up.
///
/// # The block, stated exactly
///
/// `SEC-027` is **not** blocked on hardware or on the item. It is blocked on one
/// implementation route and on a governance constraint, and both are specific:
///
/// 1. **Every available crate is a thin `unsafe` FFI wrapper.** `pkey_mprotect`
///    and friends expose `pkey_alloc`/`pkey_mprotect`/`pkey_free` as `unsafe`
///    functions taking raw pointers and `c_int` flags. There is no safe API in the
///    ecosystem the way `nix` and `landlock` provide one for `setuid` and Landlock.
/// 2. **`qqq-sys` may not contain `unsafe`.** `SAFETY.md`'s ledger requires a
///    written safety argument *and a second maintainer* (`GOV-008`, bus factor 1).
///    Neither exists, and `ARCH-009`'s test enforces it: adding `allow(unsafe_code)`
///    to this crate fails the build.
///
/// So this is the same shape as `SEC-019` and `SEC-026` were *before* safe wrappers
/// were found — except that here the search came up empty. Recording which of the
/// two it is matters: a reader who cannot tell will redo the search.
///
/// # What is deliberately not done
///
/// No `sysconf(_SC_PKEY_...)` call and no `pkey_alloc` probe. Both would answer the
/// question more directly and both need `unsafe`, which is the thing being avoided.
/// The CPU feature bit is the correct proxy: the kernel only offers the pkey
/// syscalls on hardware that advertises it.
#[must_use]
pub fn mpk_support() -> bool {
    cpu_has_pku()
}

/// Whether the CPU advertises `pku` (or the aarch64 equivalent).
///
/// # Why `/proc/cpuinfo` rather than `std::arch::is_x86_feature_detected!`
///
/// `is_x86_feature_detected!("pku")` would be cleaner and is not usable: stable
/// Rust does not expose `pku` as a recognised feature string, and detecting it via
/// `__cpuid` needs `unsafe`. Reading the kernel's own report is safe, works on
/// every architecture, and reports what the *kernel* believes rather than what the
/// CPU claims — which is the property that matters, since a kernel built without
/// MPK support will not offer the syscalls even on capable silicon.
#[cfg(target_os = "linux")]
fn cpu_has_pku() -> bool {
    // `/proc/cpuinfo` on aarch64 lists "Features" including the pkey-relevant bits;
    // on x86-64 the flag is literally `pku`. Matching on either keeps this working
    // on the two architectures §7.5's table targets.
    let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") else {
        // No `/proc` means this is not a Linux environment in any useful sense.
        // Reporting `false` is the conservative answer: a caller that believes MPK
        // exists and is wrong will fault.
        return false;
    };
    cpuinfo
        .lines()
        .filter(|l| l.starts_with("flags") || l.starts_with("Features"))
        .any(|l| l.split_whitespace().any(|f| f == "pku" || f == "pkeys"))
}

#[cfg(not(target_os = "linux"))]
fn cpu_has_pku() -> bool {
    // MPK exists on Windows and macOS under other names, and neither is wired here.
    // `false` is the honest answer for "QQQ can use it", which is the question this
    // function answers.
    false
}

/// Detect Landlock availability without installing a ruleset.
///
/// # Why this exists separately from `apply_landlock`
///
/// A deployment deciding whether to *request* Landlock needs to know whether the
/// kernel has it before it configures a policy. Asking by installing a ruleset is
/// irreversible — the process cannot undo it — so the question must be answerable
/// without side effects. This reads the kernel's own Landlock ABI report.
#[cfg(target_os = "linux")]
#[must_use]
pub fn landlock_available() -> bool {
    // `landlock` exposes the probe through its own compatibility type. Using it
    // rather than hand-rolling a `landlock_create_ruleset` call keeps this safe and
    // keeps the ABI knowledge in the crate that owns it.
    use landlock::{Access, AccessFs, Ruleset, RulesetAttr, ABI};
    // `handle_access` on a default ruleset queries the kernel ABI. If the kernel
    // has no Landlock, the crate reports an error rather than an ABI, and this
    // returns false. No ruleset is created and `restrict_self` is never called, so
    // nothing here is irreversible.
    Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V1))
        .is_ok()
        // The `RulesetAttr` import is needed for `handle_access`; silencing an
        // unused-import warning is not the point -- this line exists so a reader
        // sees that only the *query* half ran.
        && ABI::V1 as u32 >= 1
}

/// Landlock is a Linux LSM, so no other platform has it.
///
/// # Why `false` and not `Unsupported`
///
/// This function answers "can QQQ use Landlock here?", and on Windows or macOS the
/// answer is no. It is not a claim that those platforms lack a sandbox — they have
/// their own, and this crate does not wire them — so a caller reading `false` should
/// not conclude the host is unprotected. A caller that needs that distinction gets
/// it from [`STEP_LANDLOCK`]'s per-step outcome, which says `Unsupported` and names
/// the platform limitation.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn landlock_available() -> bool {
    false
}

/// The optional hardening this host supports.
#[must_use]
pub fn host_capabilities() -> HostCapabilities {
    HostCapabilities {
        memory_protection_keys: mpk_support(),
        landlock: landlock_available(),
    }
}

/// Apply the hardening steps in [`STEP_ORDER`].
///
/// # Never fails
///
/// Returns a [`HardenReport`] describing what happened. See that type for why
/// this is not a `Result`.
#[must_use]
pub fn harden(policy: &HardenPolicy) -> HardenReport {
    let mut report = HardenReport::new();

    report.push(apply_no_new_privs());
    report.push(apply_drop_gid(policy));
    report.push(apply_drop_uid(policy));
    report.push(apply_landlock(policy));
    report.push(apply_seccomp(policy));

    report
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod imp {
    use super::{
        HardenPolicy, SeccompProfile, StepOutcome, STEP_DROP_GID, STEP_DROP_UID, STEP_LANDLOCK,
        STEP_NO_NEW_PRIVS, STEP_SECCOMP,
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
    /// Apply a Landlock filesystem ruleset (`SEC-026`).
    ///
    /// # What Landlock adds that the capability engine does not
    ///
    /// The capability engine decides what the *guest* may ask for. Landlock
    /// restricts what a **compromised host process** can do if a guest finds a way
    /// past Wasm entirely — the escape §7.2 lists as "nation-state against the
    /// sandbox". §7.5 calls this depth behind the boundary, and it is precisely
    /// because it is depth that it is allowed to be the weakest layer: a host whose
    /// kernel lacks Landlock is still safe, which is what makes QQQ deployable
    /// anywhere.
    ///
    /// # Why the kernel version matters, and why it is reported rather than assumed
    ///
    /// Landlock landed in Linux 5.13. Older kernels return `ENOSYS`, and the
    /// distinction between "the kernel has no Landlock" and "the kernel refused my
    /// ruleset" is the difference between an expected skip and a real fault. So the
    /// error is inspected rather than caught: `ENOSYS` and `EOPNOTSUPP` become
    /// `Unsupported` with an explanation, and everything else becomes `Failed`.
    ///
    /// # Why an empty path list is refused rather than applied
    ///
    /// A ruleset with no rules denies every handled access, so applying one with an
    /// empty list would leave the process unable to open a file — an instant,
    /// confusing outage. The caller asked for Landlock but named nothing to keep,
    /// which is a configuration error, and it is reported as one.
    pub(super) fn landlock(policy: &HardenPolicy) -> StepOutcome {
        // `Access` and `Compatible` are traits, so they must be in scope for
        // `AccessFs::from_all` and `Ruleset::compatibility` to resolve. Both are
        // imported deliberately rather than via a glob: `from_all` is the access
        // mask that decides *which* filesystem rights the ruleset handles, and
        // `compatibility` is the setting that decides whether a weaker ruleset is
        // accepted silently -- the two most security-relevant choices in this
        // function, so they should be visible at the call site.
        use landlock::{
            Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
            RulesetCreatedAttr, RulesetStatus, ABI,
        };

        if !policy.landlock {
            return StepOutcome::skipped(
                STEP_LANDLOCK,
                "Landlock was not requested; §7.5 treats it as defence in depth \
                 rather than as the guest boundary",
            );
        }

        if policy.landlock_read_paths.is_empty() {
            return StepOutcome::failed(
                STEP_LANDLOCK,
                "Landlock was requested with no readable paths, which would deny \
                 every filesystem access the ruleset handles and leave the process \
                 unable to open a file. Name at least one directory in \
                 `landlock_read_paths`, or turn `landlock` off.",
            );
        }

        // # Why the ABI is probed rather than assumed, and why `HardRequirement`
        //
        // `set_compatibility(CompatLevel::HardRequirement)` makes every subsequent
        // build call **error** when the running kernel cannot enforce a requested
        // right. The crate's own documentation states the default: unsupported
        // features "are silently ignored by default, which is a sane choice for
        // most use cases" -- and it is the wrong choice here, because a silently
        // reduced ruleset reports success while restricting less than the policy
        // states. That is the `§O-085` shape: a control that is installed and does
        // less than it claims.
        //
        // The call must come BEFORE `handle_access`, because it governs the build
        // methods that follow it.
        let ruleset = match Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI::V1))
            .and_then(Ruleset::create)
        {
            Ok(created) => created,
            Err(e) => return classify_landlock_error(&e),
        };

        // Every path is resolved individually and the first failure names the path.
        // A `PathFd::new` failure is usually a typo or a path absent on this host,
        // and "the ruleset was rejected" without the path sends the reader to the
        // wrong place.
        let mut applied = 0usize;
        let mut created = ruleset;
        for path in &policy.landlock_read_paths {
            let fd = match PathFd::new(path) {
                Ok(fd) => fd,
                Err(e) => {
                    return StepOutcome::failed(
                        STEP_LANDLOCK,
                        format!(
                            "the Landlock path {} could not be opened: {e}. A \
                             non-existent path is reported rather than skipped, \
                             because ignoring it would leave the process with fewer \
                             filesystem rights than the operator intended, and the \
                             symptom would appear somewhere unrelated.",
                            path.display()
                        ),
                    );
                }
            };
            match created.add_rule(PathBeneath::new(fd, AccessFs::from_read(ABI::V1))) {
                Ok(next) => {
                    created = next;
                    applied += 1;
                }
                Err(e) => {
                    return StepOutcome::failed(
                        STEP_LANDLOCK,
                        format!("the Landlock rule for {} was refused: {e}", path.display()),
                    );
                }
            }
        }

        match created.restrict_self() {
            // # Why the status decides between Applied and Unsupported
            //
            // `RulesetStatus` is the crate's own three-valued answer, and it is a
            // better signal than any errno: `NotEnforced` means the kernel ignored
            // the ruleset entirely, which is an environment answer and must be
            // reported as `Unsupported` rather than as a success. Reporting it as
            // `Applied` would be a hardening step that does nothing while the
            // report reads clean -- the exact defect this module has already
            // produced once by accident.
            Ok(status) => match status.ruleset {
                RulesetStatus::FullyEnforced => StepOutcome::applied_with(
                    STEP_LANDLOCK,
                    format!(
                        "{applied} read rule(s) fully enforced (Landlock ABI {:?}, \
                         no_new_privs={})",
                        status.landlock, status.no_new_privs
                    ),
                ),
                // Partial enforcement at `HardRequirement` means the kernel
                // enforced a subset despite the request. Treated as a failure: the
                // operator asked for full coverage and did not get it.
                RulesetStatus::PartiallyEnforced => StepOutcome::failed(
                    STEP_LANDLOCK,
                    format!(
                        "the kernel enforced only part of the requested Landlock \
                         ruleset (ABI {:?}). Partial enforcement at \
                         HardRequirement means the sandbox is weaker than the \
                         policy states, which must be visible rather than \
                         reported as applied.",
                        status.landlock
                    ),
                ),
                RulesetStatus::NotEnforced => StepOutcome::unsupported(
                    STEP_LANDLOCK,
                    format!(
                        "{applied} rule(s) were built, but the kernel did not \
                         enforce them (Landlock ABI {:?}). This requires Linux \
                         5.13+; §7.5 lists Landlock as defence in depth behind the \
                         capability engine, so its absence is not a defect.",
                        status.landlock
                    ),
                ),
            },
            Err(e) => classify_landlock_error(&e),
        }
    }

    /// Decide whether a Landlock construction failure is the environment or a fault.
    ///
    /// # Why this does not simply catch everything
    ///
    /// Treating every error as "this kernel has no Landlock" makes the report green
    /// on any host, including one whose ruleset was genuinely refused. That is the
    /// `§O-085` shape once more: a control that reports success while doing
    /// nothing. Only the errors that *mean* "unsupported" are classified that way.
    fn classify_landlock_error(e: &landlock::RulesetError) -> StepOutcome {
        let text = e.to_string();
        // `landlock` renders its errors with the errno name, which is the only
        // stable signal the crate exposes.
        let unsupported = text.contains("ENOSYS")
            || text.contains("EOPNOTSUPP")
            || text.contains("not supported");
        if unsupported {
            StepOutcome::unsupported(
                STEP_LANDLOCK,
                format!(
                    "this kernel does not support the requested Landlock features \
                     ({text}); Landlock requires Linux 5.13 or newer. §7.5 lists it \
                     as defence in depth behind the capability engine, so its \
                     absence is not a defect."
                ),
            )
        } else {
            StepOutcome::failed(
                STEP_LANDLOCK,
                format!(
                    "the kernel refused the Landlock ruleset: {text}. A refusal is \
                     reported as a failure rather than as an unsupported platform, \
                     because treating it as unsupported is how a hardening step \
                     comes to do nothing while the report reads clean."
                ),
            )
        }
    }

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
            rules.insert(nr, Vec::new());
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
            let mut m = HashMap::new();
            insert_portable_syscalls(&mut m);
            insert_optional_syscalls(&mut m);
            m
        });

        table.get(name).copied()
    }

    /// The syscalls present on every supported Linux architecture.
    ///
    /// # Why this is a separate function from [`insert_optional_syscalls`]
    ///
    /// Two reasons, in order of importance.
    ///
    /// **It is the honest split.** These entries exist everywhere; the ones in the
    /// sibling function are added only where the architecture provides them. Merging
    /// them hid that distinction behind one long list, and a reader could not tell
    /// which names were guaranteed.
    ///
    /// **`clippy::too_many_lines` at 1.98 requires it.** The combined function
    /// reached 146 lines against a threshold of 100, and the failure appeared only
    /// when the container was given CI's toolchain version -- 1.97 was content. The
    /// refactor is one the lint asked for and the code wanted anyway.
    ///
    /// `libc::SYS_*` are `c_long`; the target is `i64`. On 64-bit Linux those are
    /// the same type, so an explicit conversion is a no-op that clippy 1.98 rejects
    /// as `useless_conversion`, while on a 32-bit target it would be required. The
    /// supported architectures here are all 64-bit, and the test below pins that
    /// assumption rather than leaving it implicit.
    fn insert_portable_syscalls(m: &mut std::collections::HashMap<&'static str, i64>) {
        insert_process_and_memory_syscalls(m);
        insert_io_and_poll_syscalls(m);
        insert_network_and_fs_syscalls(m);
    }

    /// Process lifecycle, signals, memory, and the thread primitives a guest
    /// runtime cannot work without.
    fn insert_process_and_memory_syscalls(m: &mut std::collections::HashMap<&'static str, i64>) {
        macro_rules! syscalls {
            ($($name:literal => $const:expr),* $(,)?) => {
                $( m.insert($name, $const); )*
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
            "getuid" => libc::SYS_getuid,
            "geteuid" => libc::SYS_geteuid,
            "getgid" => libc::SYS_getgid,
            "getegid" => libc::SYS_getegid,
            "getgroups" => libc::SYS_getgroups,
            "uname" => libc::SYS_uname,
            "sysinfo" => libc::SYS_sysinfo,
        }
    }

    /// Descriptor I/O, readiness polling, timers, and random bytes.
    fn insert_io_and_poll_syscalls(m: &mut std::collections::HashMap<&'static str, i64>) {
        macro_rules! syscalls {
            ($($name:literal => $const:expr),* $(,)?) => {
                $( m.insert($name, $const); )*
            };
        }
        syscalls! {
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
            "clock_gettime" => libc::SYS_clock_gettime,
            "clock_nanosleep" => libc::SYS_clock_nanosleep,
            "nanosleep" => libc::SYS_nanosleep,
            "gettimeofday" => libc::SYS_gettimeofday,
            "timerfd_create" => libc::SYS_timerfd_create,
            "timerfd_settime" => libc::SYS_timerfd_settime,
            "timerfd_gettime" => libc::SYS_timerfd_gettime,
            "getrandom" => libc::SYS_getrandom,
        }
    }

    /// Sockets and the filesystem.
    fn insert_network_and_fs_syscalls(m: &mut std::collections::HashMap<&'static str, i64>) {
        macro_rules! syscalls {
            ($($name:literal => $const:expr),* $(,)?) => {
                $( m.insert($name, $const); )*
            };
        }
        syscalls! {
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
        }
    }

    /// Syscalls added only on the architectures that provide them.
    ///
    /// Keeping these separate is deliberate: a reader can tell at a glance which
    /// names are guaranteed to resolve and which depend on the target.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn insert_optional_syscalls(m: &mut std::collections::HashMap<&'static str, i64>) {
        macro_rules! syscalls {
            ($($name:literal => $const:expr),* $(,)?) => {
                $( m.insert($name, $const); )*
            };
        }
        syscalls! {
            "clone3" => libc::SYS_clone3,
            "rseq" => libc::SYS_rseq,
            "set_robust_list" => libc::SYS_set_robust_list,
            "get_robust_list" => libc::SYS_get_robust_list,
            "sched_getaffinity" => libc::SYS_sched_getaffinity,
            "set_tid_address" => libc::SYS_set_tid_address,
            "rt_sigtimedwait" => libc::SYS_rt_sigtimedwait,
            "restart_syscall" => libc::SYS_restart_syscall,
            "arch_prctl" => libc::SYS_arch_prctl,
            "memfd_create" => libc::SYS_memfd_create,
            "close_range" => libc::SYS_close_range,
            "epoll_pwait2" => libc::SYS_epoll_pwait2,
            "sendmmsg" => libc::SYS_sendmmsg,
            "recvmmsg" => libc::SYS_recvmmsg,
            "openat2" => libc::SYS_openat2,
            "faccessat2" => libc::SYS_faccessat2,
            "renameat2" => libc::SYS_renameat2,
            "copy_file_range" => libc::SYS_copy_file_range,
            "io_uring_setup" => libc::SYS_io_uring_setup,
            "io_uring_enter" => libc::SYS_io_uring_enter,
            "io_uring_register" => libc::SYS_io_uring_register,
        }
    }

    /// No optional syscalls on architectures without the entries above.
    ///
    /// Present so `syscall_number` can call it unconditionally, which keeps the
    /// supported/unconditional split in one place instead of in a `cfg` inside a
    /// closure body.
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    fn insert_optional_syscalls(_m: &mut std::collections::HashMap<&'static str, i64>) {}
}

// ---------------------------------------------------------------------------
// Non-Linux implementation
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::{
        HardenPolicy, StepOutcome, STEP_DROP_GID, STEP_DROP_UID, STEP_LANDLOCK, STEP_NO_NEW_PRIVS,
        STEP_SECCOMP,
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

    pub(super) fn landlock(_policy: &HardenPolicy) -> StepOutcome {
        StepOutcome::unsupported(
            STEP_LANDLOCK,
            "Landlock is a Linux LSM (5.13+). §7.5 lists it as defence in depth \
             behind the capability engine, so its absence is not a defect: a host \
             without Landlock is still safe against a malicious guest. macOS and \
             Windows have their own sandbox mechanisms and are not wired here.",
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
fn apply_landlock(policy: &HardenPolicy) -> StepOutcome {
    imp::landlock(policy)
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
fn apply_landlock(policy: &HardenPolicy) -> StepOutcome {
    imp::landlock(policy)
}
#[cfg(not(target_os = "linux"))]
fn apply_seccomp(policy: &HardenPolicy) -> StepOutcome {
    imp::seccomp(policy)
}
