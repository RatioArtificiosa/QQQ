# Source reconciliation

Implements Checklist `DOC-013`. Tracks every correction made to the source corpus,
kept in sync with the Proposal's [Appendix A](../QQQ-Proposal-V1.md#appendix-a--source-document-reconciliation)
and the Observations' `§C-NNN` entries.

**Generated.** Run `python tools/gen_reconciliation.py` to rebuild;
`tools/check_reconciliation.py` fails CI when it drifts from either source.

---

## Why three places hold the same information

That is the obvious objection, and the answer is that each serves a different reader:

| Location | Reader | Question answered |
|---|---|---|
| **Appendix A** (Proposal) | someone evaluating the design | *was the brief followed?* |
| **`§C-NNN`** (Observations) | someone auditing a claim | *why was it wrong, and what did we learn?* |
| **This file** | a contributor | *what do I need to know before trusting a source?* |

The risk is drift between them, which is why there is a machine check rather than a
note. `tools/check_xrefs.py` check `[8]` already asserts A↔`§C` parity; this file adds
the third leg and is verified by `check_reconciliation.py`.

---

## The corrections

<!-- GENERATED:BEGIN -->

| # | Source claim | Status | What changed |
|---|---|---|---|
| A-1 | `docs/QQQAI-Full-Conversation-Complete.md` describes Bun's "11-day Zig→Rust rewrite with 13,000+ unsafe memory blocks" as fact | **Unverifiable — treat as hearsay** | This claim originated in an AI-generated attachment and cannot be verified from primary sources. Our proposal must not rest on it. Bun is a serious engineering effort; we compete on architecture, not on the premise that they did it badly. |
| A-2 | "Bun is 42,000+ RPS" | **Unverified and version-dependent** | Numbers like this are hardware- and workload-specific and rot within months. We cite *our own* measured numbers only, with methodology. |
| A-3 | "Wasmtime" recommended without a version | **Corrected** | Pinned to **Wasmtime 48.x** (crates.io `newest` at time of writing: `48.0.2`, published 2026-09-10; `49.0.0-rc.1` is a release candidate). Engine upgrades are a scheduled activity, not an accident. |
| A-4 | WASI version never stated; implicitly Preview 2 | **Corrected** | QQQ targets **WASI 0.3 (Preview 3)**, which adds native `async`, `stream` and `future`. `wasi-http` in Wasmtime now has p3 enabled by default. Preview 2 remains supported for compatibility. |
| A-5 | `qqq` as crate/CLI name | **Corrected** | `qqq` is **taken on crates.io** (v0.2.0) and on npm (v0.0.6); `github.com/qqq` is an existing user account. Decision: product **QQQ**, CLI/crate/npm **`qqqai`** (verified free on all three), domain **qqq.codes**. |
| A-6 | "Open source with MIT or Apache-2.0" (NN-8) vs. the later instruction to charge businesses | **Genuine conflict, resolved** | §13.2: Apache-2.0 for the runtime (satisfying NN-8); commercial licence for the additive Fabric governance layer (satisfying the business requirement). The conflict is documented rather than hidden. |

<!-- GENERATED:END -->

**Also corrected silently throughout:** the source corpus uses "framework" loosely.
The Proposal uses **runtime** for the thing you install and **framework** only for the
app-facing layer built on it — see
[`contributing/claims-policy.md`](contributing/claims-policy.md).

---

## What each correction has in common

Worth stating, because the pattern is the useful part rather than the six rows:

**Every one is a claim that was *plausible* rather than checked.** A version number
nobody pinned, a benchmark nobody reproduced, a name nobody looked up. None of them
would have been caught by review, because each reads as the kind of thing someone would
have verified.

That is the same failure this repository records repeatedly in code — an installed
control nobody exercised (`§O-085`, `§O-088`), and a validator whose self-test found
dead checks (`§O-092`). In documents the symptom is different and the cause is
identical: **the confident form of an unverified statement is indistinguishable from a
verified one.**

Which is why `DOC-014`'s claims policy exists, and why it distinguishes "measured" from
"derived" from "intended" rather than treating all three as assertions.

---

## Adding a correction

1. Add the row to the Proposal's Appendix A.
2. Add the `§C-NNN` entry to the Observations, with the full reasoning.
3. Run `python tools/gen_reconciliation.py` to regenerate this file.
4. `python tools/check_xrefs.py` (check `[8]`) and `python tools/check_reconciliation.py`
   both verify the three agree.

If step 3 is forgotten, CI fails and names the command — a generated file that silently
lags its source is worse than no generated file, because it looks authoritative.
