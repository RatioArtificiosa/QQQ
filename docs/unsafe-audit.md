# `unsafe` audit — the exception crates

**Item:** `SEC-020` — *Audit every `unsafe` block in the three exception crates and
record the findings.*
**Scope:** the whole `QQQ` workspace, not only the exception crates, because a
finding in a crate that is *supposed* to forbid `unsafe` is a more serious
finding than one in a crate that is allowed to have it.

---

## 1. The findings

**There are zero `unsafe` blocks in this workspace.**

| Measure | Count |
|---|---|
| `.rs` files scanned under `crates/` | **151** |
| Code-position `unsafe` (`unsafe { }`, `unsafe fn`, `unsafe impl`, `unsafe trait`, `unsafe extern`) | **0** |
| `#[allow(unsafe_code)]` in a code position | **0** |
| `cfg_attr(..., allow(unsafe_code))` | **0** |
| Crates carrying a bare `#![forbid(unsafe_code)]` | **11** (every crate) |
| Occurrences of the token `unsafe` in comments or strings | 0 (the scanner strips prose) |

**Reproduce with `python tools/audit_unsafe.py`.** It exits non-zero if any
code-position `unsafe` exists, so it is a gate rather than a report.

**The counts above are checked, not copied.** `python tools/audit_unsafe.py --check-doc`
fails when this table disagrees with a live scan, and CI runs it. It was added because the
file count here said **85** while the tree held 139: true when written, never tied to the
tree afterwards, and wrong in the direction that understates the sample.

It has since caught the same drift three times, and every time it was a red CI run waiting for a
push, which is the mechanism doing its job. The first was **141 → 142**, when
`qqq-host/src/guest_output.rs` landed. The second was **142 → 143**, from
`crates/qqq-serve/tests/accept_bound.rs`, which arrived with the per-tenant connection
ceiling. The third is **143 → 146**, from three files in one session:
`crates/qqq-pkg/src/signature.rs`, `crates/qqq-run/src/verify.rs`, and
`crates/qqq-run/src/style.rs`. The fourth is **146 → 147**, from
`crates/qqq-run/tests/worker_pool.rs`.

**Four drifts in one working period, and every one was caught by CI rather than locally.** That
is the mechanism working, and it is also a fact worth stating plainly: this number changes
whenever *any* `.rs` file is added under `crates/`, including a test file whose subject has
nothing to do with `unsafe`. The counting is deliberately broad — a safety document should not
narrow its own sample — so the churn is the price of that choice rather than a defect in the
check. Whoever adds a file should expect this, and the fix is one command:

```
python tools/audit_unsafe.py --check-doc   # prints the pair that disagrees
``` The number above is read from the scanner, never from memory: to
update this document, run the tool and copy its summary line, or let `--check-doc` print the pair
of numbers that disagree.

A safety document
whose own sample size has drifted is the "zero for the wrong reason" problem in miniature —
a reader cannot tell whether the count was right and the tree grew, or whether the scanner
was looking elsewhere the whole time.

## 2. Why the count is zero, which matters more than the count

A zero that appears for the wrong reason is worse than a non-zero, because it
looks like an achievement. There are two candidate explanations, and they have
opposite implications:

| Explanation | Implication |
|---|---|
| The audit missed the blocks | The real count is unknown, and the audit is decoration |
| The primitives that would need `unsafe` are **not yet built**, and the ones that *were* built avoided it | The count is genuinely zero, and it will stay zero as long as a safe path exists |

**It is the second, and here is the evidence for each part.**

*The audit is not blind.* The scanner was verified by **injecting** an `unsafe`
block into `crates/qqq-sys/src/lib.rs` and confirming it was detected,
classified as `[block]`, and caused a non-zero exit. A scanner that reports zero
because it is broken cannot pass that test; this one did.

*The primitives are mostly not built.* §4.3 names three exception crates —
`qqq-io-uring`, `qqq-mem-hugepage`, `qqq-sys-signals` — and this workspace carries
`qqq-sys` as one crate for all three (a recorded deviation, `§O-059f`). None of
the three concerns has been implemented: there is no `io_uring` ring, no
hugepage-backed memory, and no signal handler.

*And `SEC-019` — the one item that did need OS primitives — avoided `unsafe`
entirely.* `prctl(PR_SET_NO_NEW_PRIVS)`, `setuid`/`setgid`/`setgroups` and
`seccomp-BPF` are all reachable through safe wrappers (`nix`, `seccompiler`), so
the item that looked most likely to open the exception was implemented without
touching it. That is `§O-081`, and it is the strongest available evidence that the
zero is structural rather than accidental.

## 3. What the audit covers, and what it cannot

**Covered.** Every `.rs` file in the workspace, including test files and any
future examples, with the four code-position forms and both lint escapes. Prose is
separated rather than counted, so a doc comment *about* `unsafe` does not inflate
the figure — and a code `unsafe` cannot hide by sitting on a line that also
contains a `//`.

**Not covered, and named rather than implied:**

* **Procedural macros and build scripts.** A `build.rs` can generate `unsafe`
  code, and a proc macro can emit an `unsafe` block into a caller. Neither exists
  in this workspace today; if one appears, this scanner will not see what it
  *generates*, only what is committed. A `cargo expand` diff would be needed, and
  that is a real gap rather than a hypothetical one.
* **Dependencies.** `libc`, `nix`, `seccompiler`, `wasmtime` and every other crate
  contain `unsafe`. That is the point of using them, and their audits are theirs.
  The `cargo deny` advisory check in `ci.yml` is what covers the supply-chain half.
* **Soundness.** This counts and classifies; it does not evaluate. With zero
  blocks there is nothing to evaluate, and the moment there is, `SAFETY.md` §5's
  reviewer checklist is what applies.

## 4. What happens when the first `unsafe` lands

The audit is a **snapshot**. Its value is that it is re-runnable, and the
enforcement that makes the *next* one safe already exists:

| Control | Where | What it does |
|---|---|---|
| The exception is granted through a process | `crates/qqq-core/tests/architecture.rs::the_unsafe_exception_was_granted_through_its_process` | An `allow(unsafe_code)` with no `SAFETY.md` beside it fails the build |
| No non-exception crate may permit it | `...::every_non_exception_crate_forbids_unsafe_code` | Dropping a `forbid`, or weakening it to `cfg_attr`, fails |
| The exception list names real crates | `...::the_unsafe_exception_list_names_real_crates` | A stale list that exempts nothing fails |
| The lint policy is live | `tools/fault_inject_architecture.py` | Injects a bare `allow(unsafe_code)` and fails if it is not detected |
| The safety argument is enforced as a document | `crates/qqq-sys/SAFETY.md` §6, §7 | The ledger's rows 2 and 3 must change before `unsafe` may be added |

**And the process is currently blocked, which this audit confirms rather than
discovers.** `SAFETY.md`'s ledger records that no second maintainer exists
(`GOV-008`, bus factor 1, risk `R-15`), and §4.3 requires the argument be *"reviewed
by a second maintainer"*. So the honest statement is: **the workspace contains no
`unsafe`, and the process that would govern the first one is enforced but cannot
currently complete.** That is a governance gap, not a code gap, and it is recorded
in Observations rather than left as an implication of a zero.

## 5. Re-run schedule

The audit runs whenever this claim is made, and the mechanism that keeps it honest
is that it is cheap and scripted: `python tools/audit_unsafe.py`, seconds, exit
code meaningful. No schedule is needed — the *architecture tests* run on every
commit and already fail if the lint policy changes, which is the property a
schedule would be trying to approximate.
