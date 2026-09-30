# Definition of Ready — the admission rule for items and for observations

**Status:** normative for `PLAN-009` and `PLAN-015`. **One rule serves both**, which is why the two were
recorded together: an item and a decision both answer *"what may be written down, and what must be true before
it is"*.

**The gap this closes, in the checklist's own words:**

> *"That item needs an **admission rule for decisions**; this one needs an **admission rule for items**. Both
> answer 'what may be written down, and what must be true before it is' — **one rule serves both**."*
>
> *"**The gap is the PART OF SPEECH before the writing, not the writing.**"*

---

## 1. The rule, in one sentence

**What may be written down is a claim; what must be true before it is written is that its author can name the
observation that would falsify it.**

That is the whole rule. Everything below is what it means for the three things this repository writes down:
a checklist item, a decision, and an observation.

## 2. Why this wording and not "must have a clear acceptance test"

`PLAN-009` says *"clear acceptance test"*, and **"clear" is a reader's judgement** — which the checklist
already records:

> *"nothing states what makes an item's acceptance test clear, and `tools/check_done_lines.py` enforces only
> that a `[x]` **has** a `→ Done:` line and a `[~]`/`[!]` **has** a reason; whether either names something
> checkable is a reader's judgement."*

**"Name what would falsify it" is the same requirement made checkable**, because a falsifier is either:

* **a number** — `2104 of 2280`, `547 passed`, `depth: 0`;
* **a path** — `crates/qqq-run/src/build.rs:1252`;
* **a command with its exit code** — `self_test_xrefs.py` → `SELF-TEST PASSED`;
* **or an explicit statement that no observation would falsify it, with the reason** — which is what a
  *proposal* item is, and is honest rather than exempt.

## 3. The three admitted forms

| what | admission requires | what is refused |
|---|---|---|
| **a checklist item** | an acceptance test naming one of the four falsifiers in §2, or the `→ §` reference plus a reason | *"improve X"* with nothing that could show it failed |
| **a decision** | a `§D-NNN` entry stating the decision **and what would reverse it** | a decision recorded as a preference |
| **an observation** | a measurement — §2's first three forms | a restatement of a claim already in the corpus |

**A `[~]` or `[!]` item is not required to have a falsifier**, because it is a statement that the work is
*not* ready — **and requiring one there would fire on the 325 open items nobody has investigated yet.**
`check_done_lines.py` already encodes that asymmetry with four self-test cases including its control, and this
rule does not widen it.

## 4. What is deliberately NOT here

**No new status, no new field, no new file per item.** The entry shape is already enforced in both gates by
`tools/check_done_lines.py`, and this document does not restate it — **it states the part of speech that
precedes it.** A rule that added a field would be a fourth place for the same fact, which is the shape
`§O-466` records.

**And no exemption list.** `check_done_lines.py` carries a 53-item ratchet for `→ Done:` lines **because those
53 were ticked before the convention existed**; that is a measured exemption with a reason. **An admission
rule with an exemption list would be a rule that does not apply to whatever its author was writing.**

## 5. How it becomes executable

The rule is prose here and becomes a check in `tools/check_admission.py`, following the shape every checker in
this repository already has:

* **It reads `QQQ-Checklist-V1.md` and `QQQ-Observations-and-Memories.md`.**
* **It requires that each `→` note added after this document's landing names a falsifier**, detected as a
  digit-containing token, a path with a line number, or a checker name with its verdict.
* **It carries a control**: a note that is only a `→ §N` reference **must pass**, so the rule cannot become
  "every note needs a number".
* **And it is fault-injected**: stripping the falsifier from a note must make it report that note and exit 1.

**The ratchet is the landing date**, in the same way `check_done_lines.py`'s is a measured 53-item list: the
notes already written are not retroactively ruled inadmissible by a rule that did not exist when they were.

## 6. What this document does not close

**`PLAN-009`'s second half** — *"no unresolved dependency"* — is **partly** answered here: §2's fourth form is
where a blocked item states what would unblock it, and `blocked-by-upstream-and-time` becomes an admission
rather than a format. **But whether a *checker* can detect an unresolved dependency is a separate
measurement**, and the checklist records that *"nothing states what an unresolved dependency is, and no
checker looks for one."* **This document states it; no checker reads it yet**, and that is the honest boundary
of this landing.
