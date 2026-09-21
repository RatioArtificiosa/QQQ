# Writing claims

Implements Checklist `DOC-014`, expanding Proposal §0's vocabulary rules.

Every sentence in this project's documents is one of four kinds, and each kind has a
different **evidential requirement**. The failure this page prevents is a claim that
*reads* as verified while being an intention — which is the most expensive kind of
documentation error, because it is discovered by someone who acted on it.

---

## The four kinds

| Kind | Example | What it must carry |
|---|---|---|
| **Measured** | "Instantiation is 240 µs at p50" | The command, the hardware, the date |
| **Derived** | "A guest cannot reach an ungranted import" | The mechanism, in one sentence |
| **Intended** | "V1 will support five languages" | A milestone, and the checklist IDs |
| **Absent** | "Side channels are not defended" | What to do instead |

The distinction that matters most is the first two. A **measured** claim is a fact about
a run; a **derived** claim is a fact about the code. Neither is stronger than the other,
and conflating them produces sentences like "the sandbox is fast", which is neither.

---

## Rules

### 1. No claim without evidence

A claim in a document must be one of:

* **Measured** — with the command that produced it. `cargo bench` output pasted in is
  evidence; "we measured this" is not. If the number came from a run, the run is
  reproducible and its parameters are stated.
* **Derived** — from a mechanism named in the same paragraph. "A guest cannot reach an
  ungranted import **because the linker is built from the grant set, so the import is
  absent rather than denied**" is a derived claim with its derivation.
* **Intended** — plainly marked, with a milestone.

Anything else is a wish. The word for it is not "claim" but "goal", and goals belong in
the checklist rather than in a design statement.

### 2. Numbers carry their conditions

A performance number without its hardware, its input size and its concurrency is not a
measurement — it is a vibe with a decimal point.

```
Bad:   Instantiation is sub-millisecond.
Good:  Instantiation is 240 µs at p50 (24-core x86-64, warm pool, 2 MiB heap).
       Measured with `cargo bench -p qqq-host --bench instantiate` on 2026-09-20.
```

The "bad" version is not *wrong*. It is unfalsifiable, which is worse: a reader cannot
tell whether their workload will see the same, and neither can the author.

> **A note on the example above.** The "good" form is illustrative, and **no such
> benchmark exists in this repository yet** — instantiation timing is `PERF-*` work not
> yet done. It is written this way deliberately, because a policy document whose own
> example cites a command that does not exist demonstrates the exact failure it warns
> about. The first draft of this page did that, and it was caught by running the
> command rather than by rereading the sentence.

### 3. "Should", "will" and "is" are not interchangeable

| Word | Means | Requires |
|---|---|---|
| **is** | it does, now | a test that fails if it stops |
| **will** | it is planned | a checklist item and a milestone |
| **should** | somebody believes it ought to | — and this is why it is banned |

`should` is the most dangerous word in a design document, because it hides whether
something *happens* or merely *ought to*. Every occurrence in this project's documents
is either rewritten as `is` (with a test) or `will` (with an item), or deleted.

### 4. Capability claims name the mechanism

"The capability engine prevents a guest from reading another tenant's files" is only
usable if the reader can check it. The usable form names what does the preventing:

> A guest holds an **opaque handle**, not a path, so there is no value it could supply
> that names another tenant's file. The engine is `qqq-cap::resolve`, and the property
> is asserted by `no_overlay_can_ever_widen`.

A reader can now disagree with a specific claim rather than with a summary.

### 5. Uncertainty is stated as a value, not as hedging

```
Bad:   This may or may not be a problem in some cases.
Good:  We have not measured this. The failure mode would be X; the check that would
       catch it does not exist yet.
```

Hedging transfers the work of interpretation to the reader while implying the author
did some. Naming the gap transfers it back, and it is *actionable*: "we have not
measured this" tells someone what to do next.

---

## Vocabulary

These are the project's usage rules. Where the industry disagrees, these win.

| Term | Use it for | Do not use it for |
|---|---|---|
| **host** | the native `qqqai` process | the machine, the OS, the container |
| **guest** | a WebAssembly component being executed | a tenant, a user, a request |
| **component** | a Component Model binary (`version 0x1000d`) | a core module, a `.wasm` file of unknown type |
| **capability** | a *grant* of authority | a feature, an ability, a function |
| **sandbox** | the isolation boundary (Wasmtime's) | the capability model — they are different layers |
| **framework** | something that calls your code | something your code calls |
| **runtime** | something your code calls that executes your code | a framework |
| **verify** | ran a command and read the output | reasoned about it |
| **validate** | an *external* party attempted to break it | any internal check |

### Framework versus runtime

Called out because it is the mistake this project's own naming invites. QQQ is a
**runtime**: you call it, it executes your code, and it does not dictate your program's
structure. A framework inverts that control.

The distinction is not pedantry — it predicts what a user should expect. Someone who
expects a framework will look for QQQ to structure their application and will be
confused by finding a CLI and a library. §8's agent-facing design depends on the
runtime framing being understood.

### `verify` versus `validate`, and why this project is strict about it

This one carries the most weight, because it is where a security claim can be
technically true and practically misleading.

* **Verify** — the author ran something and read the result. `cargo test` verifying a
  boundary is verification.
* **Validate** — an *adversary* attempted to break it and failed. That has not happened
  here: `SEC-024` and `SEC-025` are uncommissioned.

So this project says "the capability model is verified by tests" and **not** "the
capability model is validated". The threat model's §4 carries a "validated by an
adversary?" column reading `No` for every row, and
`tools/check_threat_model.py` fails the build if a claim of external validation appears
while those items are open.

---

## Applying these rules

**In review.** A sentence without an evidentiary kind is the thing to flag. It is
usually fixable in place: name the mechanism, add the command, or mark it as intended.

**In code comments.** A comment stating a behaviour should name the test that would
fail if the behaviour changed. `// This cannot overflow` is a claim; `// Bounded by
MAX_LEN, asserted in handles::tests::the_table_is_bounded` is evidence.

**In commit messages.** State what was measured, not what was attempted. "clippy clean
under 1.97 and 1.98" is a fact; "fixed the lints" is a summary that could be true of
several things.

**In a blocked item.** Name the block and what would unblock it. "Blocked on `GOV-008`:
needs a second maintainer, which requires hiring" is usable. "Blocked" alone is not.
