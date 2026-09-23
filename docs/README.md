# QQQ documentation

Entry point for this repository's documentation. **Three documents are normative**
(the Proposal, the Checklist and the Observations); everything else explains,
generates from, or verifies them.

---

## The three-document system

QQQ's design is tracked in three files at the repository root. They are not three
drafts of one document — each has a different job, and conflating them is the mistake
this structure exists to prevent.

| Document | Job | Changes when |
|---|---|---|
| [`QQQ-Proposal-V1.md`](../QQQ-Proposal-V1.md) | **What and why.** The design: architecture, security model, performance targets, milestones. Normative. | The design changes |
| [`QQQ-Checklist-V1.md`](../QQQ-Checklist-V1.md) | **What remains.** 580+ items, each citing the Proposal section it implements. Checked, partial, or blocked. | Work completes |
| [`QQQ-Observations-and-Memories.md`](../QQQ-Observations-and-Memories.md) | **What we learned.** Decisions, mistakes and their fixes, verified environment facts, corrections to the source, open questions, stubs. | Something is discovered |

**The rule that makes this work.** A claim is either in the Proposal (a design
decision) or in the Observations (an observation about reality). It is **never in
both**, and when they disagree the Observations win — because the Proposal states
intent and the Observations record what happened when the intent met a compiler.

That ordering is deliberate. A design document cannot be kept true by editing it; it is
kept true by recording where it was wrong.

---

## How the three stay in sync

The cross-reference graph is **machine-checked**; prose alone does not fail a build.

```
Proposal §6.2  ──"→ Checklist: CAP-011…"──▶  Checklist item CAP-011
                                               └──"→ §6.2 qqq-cap"──▶ Proposal §6.2
```

Both directions are required. `tools/check_xrefs.py` reports numbered checks, and two
harnesses prove each one fires, run as two phases from one entry point:

- **In place** - `tools/self_test_xrefs.py` mutates the three real documents, asserts the
  rule fires against the corpus that will be committed, and restores them. This is the
  integration proof, and it is the phase that can leave a defect behind if it is killed,
  which is why it installs signal handlers and why `--check-clean` exists.
- **Hermetic** - `check_xrefs.py --self-test` runs first, on a corpus built in a temporary
  directory that is never the repository. It exists because four checks cannot be violated
  in place without more risk than proof: `[3]` wants a repeated heading, `[5]` wants an
  uncited section, and `[7]` and `[11]` want a stub marker in a source file. It also carries
  the one case that is a **report** rather than a check - the progress line - because a
  report is a claim about the corpus and a claim nobody exercises is a claim that drifts;
  `SEC-020` and `§O-190` are both that failure.

| Check | What it rejects | Proven by |
|---|---|---|
| `[1]` | A checklist item citing a Proposal section that does not exist | in place |
| `[2]` | A Proposal line citing a checklist ID that does not exist | in place |
| `[3]` | One anchor defined twice | hermetic |
| `[4]` | A checklist item with no Proposal citation line | in place |
| `[5]` | A Proposal section no checklist item cites (reported as a warning, not a failure) | hermetic |
| `[6]` | A checklist ID defined twice | in place |
| `[7]` | A stub marker naming no checklist item, or markers with no stub section | hermetic |
| `[8]` | An Appendix A correction row with no matching Observations entry | in place |
| `[9]` | An open question numbered in one document but not the other | in place |
| `[10]` | A Proposal citation naming an undefined Observations decision | in place |
| `[10b]` | An Observations decision the Proposal never cites | in place |
| `[11]` | A stub section with no inline marker anywhere in the source | hermetic |
| `[12]` | The Observations document losing a required section, or reordering them | in place |
| `[report]` | The progress line counting fewer markers than the legend defines | hermetic |

The in-place phase **breaks the corpus on purpose** and asserts each rule fires, because
a validator that cannot fail manufactures confidence rather than safety. It also
self-heals: an interrupted run leaves fault markers behind, and the harness detects,
reverses and verifies their removal rather than letting the next validator run report
them as real document drift. Both phases run in CI, in the local Linux bridge, and in the
gate.

The validator's own module docstring lists a shorter set - the checks as originally
written. The table above is what the harnesses actually drive, which is the number to
trust: a claim about coverage should come from the thing that exercises it.

---

## Making a change

**Adding a capability or a design decision** → edit the Proposal, add a
`→ **Checklist:**` line naming the new items, then add those items with `→ §` citations
back. Run `python tools/check_xrefs.py`.

**Completing a checklist item** → tick it and add a `→ Done:` line naming the code and
the test that proves it. An item is not done because the code exists; it is done when
something would fail if the code were wrong.

**Discovering something** → record it in the Observations, whichever document it
contradicts. If it contradicts the Proposal, the Proposal is corrected in the same
change and Appendix A gains a row.

**Blocking an item** → mark it `[!]`, record the reason in the Observations, and state
what would unblock it. Before doing that, ask `§O-082`'s question: *"is this blocked on
the item, or on one way of doing it?"* It has dissolved three apparent blocks in this
project so far — and it did not dissolve the external audits, which is the point of
asking rather than assuming.

---

## This directory

| File | What it is |
|---|---|
| [`glossary.md`](glossary.md) | **Generated** from the Proposal's §0.6 table by `tools/gen_glossary.py`. Do not edit; edit the Proposal. |
| [`contributing/anchors.md`](contributing/anchors.md) | Anchor derivation and stability rules (`DOC-008`) |
| [`contributing/claims-policy.md`](contributing/claims-policy.md) | How to write claims that can be verified (`DOC-014`) |
| [`reconciliation.md`](reconciliation.md) | Every correction to the source corpus, kept in sync with Appendix A |
| [`threat-model.md`](threat-model.md) | Assets, adversaries, the code defending each, and residual risk (`SEC-001`) |
| [`out-of-scope.md`](out-of-scope.md) | What QQQ does not defend against, and what to do instead (`SEC-030`) |
| [`abi-cost-measured.md`](abi-cost-measured.md) | The measured ABI-crossing costs (`PERF-005`), replacing §9.3's estimates |
| [`advisories/`](advisories/README.md) | The public security-advisory register (`SEC-023`) |
| [`wasmtime-advisory-process.md`](wasmtime-advisory-process.md) | The 72-hour patched-engine commitment |
| [`unsafe-audit.md`](unsafe-audit.md) | The zero-`unsafe` result and how it is verified (`SEC-020`) |
| [`development-bridge.md`](development-bridge.md) | The Linux verification environment and its one-way rule |

`docs/.env` holds local credentials and is **gitignored** — it is never committed and
never referenced by a generated file.

---

## Generated files, and why they say so

`glossary.md` carries a header stating it is generated, naming its source and the
command to regenerate it. A generated document that does not say so is one that gets
hand-edited, after which the next generation silently reverts the change — a confusing
loss that looks like a tool bug rather than a workflow mistake.

`tools/check_glossary.py` verifies the generated file matches its source, so a
hand-edit fails CI instead of disappearing.

---

## Where to start

* **Evaluating QQQ** → the Proposal's §0.1, then [`out-of-scope.md`](out-of-scope.md),
  then the security model in §7.
* **Reviewing the security posture** → [`threat-model.md`](threat-model.md) — and note
  its first section, which states what has *not* been validated.
* **Contributing code** → the Checklist's §1 (areas) and §2 (phase map).
* **Understanding a decision** → search the Observations for the identifier. Every
  decision is `§D-NNN`, every observation `§O-NNN`, every mistake `§M-NNN`, every
  correction `§C-NNN`.
