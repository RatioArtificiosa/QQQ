# Safety argument — `qqq-sys`

> **Status: not yet granted.** This document is the *argument that must be made*
> before `qqq-sys` is permitted to contain `unsafe`. The crate contains no
> `unsafe` today and carries a bare `#![forbid(unsafe_code)]`.
>
> Implements Checklist `ARCH-009`. Required by Proposal §4.3:
>
> > **`unsafe` policy.** `#![forbid(unsafe_code)]` at the root of every crate
> > above. The only exceptions are three narrowly-scoped crates that require it
> > (`qqq-io-uring`, `qqq-mem-hugepage`, `qqq-sys-signals`), each with a written
> > safety argument, each reviewed by a second maintainer, each with Miri
> > coverage where applicable.
>
> The Proposal names three exception crates; this workspace additionally carries
> `qqq-sys` as a single narrow crate for OS-level primitives. That is a
> **deviation from the Proposal**, recorded here rather than left implicit, and
> recorded as `§O-059f` in Observations with the reasoning and the revisit
> trigger.

---

## 1. Why this file exists

An `unsafe` block is a promise the compiler cannot check. Every project that
allows one must be able to answer three questions about it:

1. **What invariant is being asserted?** — the thing that must be true for the
   code to be sound.
2. **Who is responsible for maintaining it?** — which code must not change, and
   what would break it.
3. **How would a mistake be caught?** — the test, the tool, or the review that
   would find it before a user did.

A file that answers none of these is decoration. This one is structured so a
reviewer can check each answer, and it is **enforced by a test**: see §6.

---

## 2. The invariant, stated before any code is written

`qqq-sys` exists to wrap OS primitives Rust's standard library does not expose or
exposes unwieldily — signals, `mmap` flags, `prctl`, `io_uring` setup. Each such
wrapper must satisfy exactly one contract:

> **Every `unsafe` call in `qqq-sys` is immediately surrounded by the validation
> that makes its preconditions true, and every safe function in `qqq-sys`
> presents a signature whose type-level contract is sufficient to call it safely
> on any input.**

Concretely, three rules:

1. **No safe function may have an unchecked precondition.** If a caller can pass
   a value that makes the call unsound, the function must be `unsafe fn` — not
   `fn` with a comment saying "must be non-zero".
2. **No raw pointer may outlive the borrow it came from.** Every FFI return that
   is a pointer is either owned immediately or tied to a lifetime.
3. **No `unsafe` block may span more than the call it exists for.** A block
   containing two operations means a reviewer cannot tell which one the safety
   comment describes.

Rule 3 is the one that decays first in practice, which is why it is stated as a
test rather than a preference (§6).

---

## 3. The hazards, and how each is contained

| Hazard | Where it appears | Containment |
|---|---|---|
| Dangling pointer from an FFI return | `mmap`, `io_uring` SQE/CQE rings | The wrapper takes ownership in the same statement; the lifetime is tied to a guard type whose `Drop` unmaps |
| Data race through shared memory | Hugepage-backed buffers | The buffer is `!Sync` by construction; sharing requires an explicit wrapper with a documented fence |
| Use of a value after the OS revoked it | Signal-handler state after `sigaction` restore | A generation counter checked at every access; stale generations return an error rather than reading |
| Uninitialised memory read | `mmap` without `MAP_ANONYMOUS`, or `MaybeUninit` | Every allocation path zero-fills unless a caller passes a typed `Uninitialised` marker, which is `unsafe` to construct |
| Integer truncation in a length passed to the OS | Any `usize` → `c_int` conversion | All length conversions go through one `try_into` helper that returns `Err` rather than truncating |
| Signal-handler reentrancy | Any `unsafe` reachable from a handler | Nothing in this crate may be called from a signal handler; enforced by keeping handler bodies to `AtomicUsize` stores, checked at review |

**The hazard that is not contained, stated plainly.** `qqq-sys` cannot defend
against a caller that passes a pointer it obtained unsoundly elsewhere. The
crate's guarantee is *local*: it does not make its own code unsound, and it does
not launder unsoundness from its callers. That boundary is why rule 1 matters —
a safe `fn` here would export a false guarantee to every crate above it.

---

## 4. Why this crate and not the three the Proposal names

| Proposal crate | Purpose | This workspace |
|---|---|---|
| `qqq-io-uring` | io_uring reactor backend (`PERF-014`) | **Merged into `qqq-sys`** — one exception crate rather than three |
| `qqq-mem-hugepage` | Hugepage-backed linear-memory backing | **Merged into `qqq-sys`** |
| `qqq-sys-signals` | Signal handling for epoch ticking | **Merged into `qqq-sys`** |

**Rationale.** Three crates with one `unsafe` policy each is three documents, three
review processes and three places the policy can drift — and `ARCH-009` requires
a written argument *per crate*, so splitting multiplies the paperwork that is
supposed to prevent drift. One crate with one document and one reviewer is
strictly stronger for the same surface area.

**The cost, stated.** One crate means one `forbid` to remove rather than three
narrow ones, so the blast radius of a mistake in the exception process is larger.
That is the real trade, and it is accepted because the policy is enforced by a
test (§6) rather than by the crate boundary.

**Revisit when.** If `qqq-sys` grows past roughly 1,500 lines, or if the three
concerns develop genuinely different review requirements, split it. The split is
mechanical — the modules already map one-to-one onto the three named crates.

---

## 5. What a reviewer must check

For each `unsafe` block, in addition to correctness:

1. **Is there a `// SAFETY:` comment naming the invariant?** One comment per
   block, and it must name the *precondition*, not restate the code.
2. **Is the block minimal?** Rule 3: one operation per block.
3. **Could this be safe?** If the precondition is checked immediately before the
   call, the function can usually be `fn` with an internal assert. `unsafe fn` is
   for a precondition the *caller* must uphold.
4. **Is there a test that fails if the invariant is broken?** Miri where the
   operation is memory-related; a targeted test where it is not.
5. **Has the second maintainer signed off?** §4.3 requires it.

---

## 6. Enforcement — what is checked, and by what

| Rule | Enforced by | Fails when |
|---|---|---|
| The crate forbids `unsafe` while it is a stub | `crates/qqq-core/tests/architecture.rs::the_unsafe_exception_was_granted_through_its_process` | an `allow(unsafe_code)` lands with no `SAFETY.md` beside it |
| No crate outside the exception list permits `unsafe` | `...::every_non_exception_crate_forbids_unsafe_code` | a crate drops its bare `forbid`, or weakens it to `cfg_attr` |
| The exception list names real crates | `...::the_unsafe_exception_list_names_real_crates` | the list goes stale and exempts nothing |
| The lint policy is live | `tools/fault_inject_architecture.py` | injection of a bare `allow(unsafe_code)` is not detected |

**What is *not* enforced, and cannot be by a test in this repository:** that the
safety argument in §3 is *correct*. That is the second reviewer's job, and
`GOV-007` (the maintainer ladder) is what makes a second reviewer exist. Until
then, `qqq-sys` stays a stub and keeps its `forbid` — which is the honest state,
and the one the enforcement above maintains automatically.

---

## 7. Status ledger

| Item | State |
|---|---|
| `qqq-sys` contains `unsafe` | **No** — `#![forbid(unsafe_code)]`, and `SEC-019` did **not** add any |
| This safety argument is complete | **No** — it is the argument *template*, written before the code, which is the correct order |
| Second maintainer exists | **No** — `GOV-008`, bus factor 1 (risk `R-15`) |
| Miri coverage configured | **No** — lands with the first `unsafe` |
| Decision to merge three crates into one | Recorded in §4 above and in `§O-059f` |

**Therefore:** no `unsafe` may be added to this crate until the ledger's second
and third rows change. That is not a stylistic preference; it is what §4.3's
"reviewed by a second maintainer" requires, and the test in §6 makes the
requirement mechanical rather than a matter of memory.

---

## 8. The block that was not deferred: `SEC-019`

`SEC-019` (Linux hardening: dropped privileges, `no_new_privs`, seccomp) is the
first item to need OS primitives this crate exists to wrap. The obvious
implementation is `libc` calls in `unsafe` blocks — which would require rows 2 and
3 of the ledger above to change first, and they cannot (`GOV-008`).

**It was implemented anyway, without adding `unsafe`**, because safe wrappers
exist: `nix` provides `setuid`, `setgid`, `setgroups` and `set_no_new_privs` as
safe functions, and `seccompiler` compiles a BPF filter from a typed description.

Two consequences worth recording:

1. **The ledger is unchanged and the invariant holds.** `qqq-sys` still contains
   no `unsafe`, so §6's enforcement tests still pass and nothing here waits on a
   second maintainer. The block was **sidestepped rather than deferred**.
2. **The trade is a dependency, and it is the better side of it.** An `unsafe`
   block we write is an obligation this project holds forever and must review at
   every change; a safe wrapper is an obligation the ecosystem holds, which we
   review once. `§O-081` records the reasoning in full.

**What this does not change.** The ledger's second and third rows still govern any
*future* `unsafe` in this crate. If `Landlock` (named as unimplemented in
`src/harden.rs`) or a raw `io_uring` ring is needed later and no safe wrapper
exists, the exception process is the path — and it remains blocked until a second
maintainer exists. Recording that here means the next person finds the constraint
rather than rediscovering it.
