# Definition of Done — for a change, and for an item's evidence

**Status:** normative for `PLAN-010`. **This is the change-shaped half** the item's own note names as missing,
and it is the companion to [`definition-of-ready.md`](definition-of-ready.md): that document says what may be
*written down*, and this one says what must be **true** before an item is called done.

**`PLAN-010`'s parenthetical names five things** — *"code, tests, docs, xref, observations updated"* — and its
own note says *"which of the four a given item requires"*. **Measured: the phrase "the four" occurs once in the
corpus and "the five" occurs zero times, so the note's number is the error.** The five are the item's, and this
document says which of the five a given change requires.

---

## 1. The rule

**An item is done when every artefact it names has been updated, and the `→ Done:` line names the command that
shows it.**

The second clause is not decoration. **`§O-474` recorded a `→ Done:` line that said `7 cases` and `556` one
round after both had moved, and nothing re-read it.** A claim about a running program must name the thing that
produces its number, or the next reader cannot tell a stale line from a current one.

## 2. The five artefacts, and when each is required

| artefact | required when | how it is verified |
|---|---|---|
| **code** | the item changes behaviour | `cargo test --workspace --all-features` |
| **tests** | the code has a contract a reader could get wrong | the test's own name, and **a fault injection** (`§O-280`) |
| **docs** | the change alters what a reader is told | `check_doc_claims.py --record` and the resolver it names |
| **xref** | the change lands a `§O-NNN`, a `§D-NNN`, or a checklist id | `check_xrefs.py` **and** `self_test_xrefs.py` |
| **observations** | the change found something durable | the `## §O-NNN` heading, before the `*End of …*` marker |

**And the three that are ALWAYS required, because they are what makes the other five checkable:**

| always | why |
|---|---|
| **`cargo fmt --all`** | it moves comments, so a coordinate measured before it is stale after it |
| **the four gate commands** | `fmt`, `clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `check_api_examples --allow 2105` |
| **both gates stay in parity** | `check_gate_parity.py`; a checker in one gate and not the other is the divergence it exists to find |

## 3. Why "code, tests, docs, xref, observations" is not checkable as written

**Because it is a list of nouns, and an item does not say which ones it needs.** `PLAN-010`'s note measures
this precisely: *"what exists here is a definition of the entry's shape"* -- `check_done_lines.py` enforces that
a `[x]` **has** a `→ Done:` line -- **and a line is not a set of artefacts.**

**The change this document makes is that the `→ Done:` line must NAME the artefacts it claims**, so the line

    -> Done: measured 547 passed.

is weaker than

    -> Done: the lib binary went 546 -> 547 passed (`cargo test -p qqq-run --all-features`), and the
       note in `crates/qqq-run/src/build.rs` moved with it.

**The first names a number; the second names a number, its command, and the second artefact.**

## 4. What is deliberately NOT here

**No per-item artefact manifest, no new field, no exemption list.** A manifest would be a fifth place for a
fact that the `→ Done:` line already carries, **and `§O-466` records what happens to a fact kept in more than
one place.** The line is the manifest.

**And no retroactive application.** Measured at landing: `check_admission.py` reports **331 claims without a
falsifier** against a **331** budget, **and that ratchet may only fall** -- so this document adds no new
burden on the notes already written. **A rule that condemned 58% of the corpus was rejected in
`§O-474`'s own investigation**; this one is written to be satisfiable by the next change rather than by a
rewrite of the last thousand.

## 5. How it becomes executable

**`tools/check_admission.py` already enforces §2's first form** -- a claim must name a number, a path, a
command with its verdict, or state why none exists -- **so the change-shaped half needs no new checker.** What
it needs is the statement that the five artefacts are the ones a `→ Done:` line may name, **and that is this
section.**

**The measurement that closes the item is therefore the existing gate**: `check_admission.py`,
`check_done_lines.py`, `check_xrefs.py`, `self_test_xrefs.py`, and `check_gate_parity.py`, all green, **with
this document cited from the item's `→ Done:` line.**

## 6. What this does not close

**V1's definition of done is Proposal §16** -- *"V1.0 ships only when every item below is true and verifiable
by a third party"*, across Correctness, Security, Performance, Usability, Agent-readiness and Sustainability,
tracked by `DOD-001` … `DOD-024`. **That is a different document about a different question**, and conflating
the two is what made `PLAN-010` look partly-met for several rounds: **it is the definition of done for an
ITEM, not for the product.**
