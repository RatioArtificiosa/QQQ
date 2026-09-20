# Architecture Decision Records

## Where decisions actually live

**The canonical decision register is `QQQ-Observations-and-Memories.md` §2
(DECISIONS), entries `§D-001` … `§D-009`.** This directory does not duplicate it.

That is a deliberate choice and not an omission. The three-document system
already has a decision register with:

* **stable identifiers** (`§D-004`) that the Proposal can cite and the
  cross-reference validator can check for dangling references;
* **one place** an owner looks, so two registers cannot drift;
* **linking checked from the Proposal to the register** by
  `tools/check_xrefs.py` check `[10]`, which fails CI when the Proposal cites a
  `§D-` identifier that does not exist.

A second register under `docs/adr/` would be a parallel list with no enforcement,
and parallel lists drift. The Observations register is what `§D-001` … `§D-009`
already are, and the ADR *process* below is what makes them maintainable.

### The citation checks run both ways

| Check | Catches |
|---|---|
| `[10]` | the Proposal cites a `§D-` identifier that does not exist |
| `[10b]` | Observations defines a `§D-` identifier the Proposal never cites |

`[10b]` was added after the one-way check missed a real problem: six of the nine
decisions were once **write-only** — they existed in Observations and appeared
nowhere in the Proposal, so a reader of the Proposal alone would never learn they
existed. `[10]` could not catch that, because it only knows about citations that
already exist. It was found by reading.

Adding the check immediately found three more dangling decisions (`§D-002`,
`§D-008`, `§D-009`), each of which is now cited where it belongs. A fault
injection in `tools/self_test_xrefs.py` strips a citation and asserts the check
fires, so it cannot silently become a check that always passes.

## When a decision needs an entry

Add `§D-0NN` to Observations §2 when a choice:

1. **cannot be cheaply reversed** — a pinned engine version, a licence boundary,
   a licence model, a crate topology;
2. **constrains future work** — "every host capability is a WIT interface first"
   (`§D-008`) dictates the shape of every later capability;
3. **will be questioned by someone who was not present** — the reason is more
   valuable than the decision, because the decision is visible in the code and
   the reason is not.

Do **not** open a decision entry for anything reversible by editing one file. A
register full of trivial entries is a register nobody reads.

## The template

```markdown
### §D-0NN — <the decision, in one line, stated as a choice made>

**Decision.** What was decided, unambiguously.

**Context.** What made this a decision rather than a default — the constraints,
the alternatives that were real, and what was unknown at the time.

**Alternatives considered.**
| Option | Why not |
|---|---|
| <the plausible one> | <the concrete reason, not "it is worse"> |

**Consequences.** What this makes easy, what it makes hard, and what it costs.
A decision with no stated cost has not been thought about.

**Revisit when.** The trigger that should reopen this — a version, a date, a
measured result. Without this, a decision becomes folklore.

**Proposal ref:** §N.N; **Checklist:** `ABC-001`, `DEF-002`.
```

## Why "Revisit when" is required

A decision without a revisit trigger is indistinguishable from an accident six
months later. `§D-003` pins Wasmtime to the 48.x line; the trigger is a published
advisory or the 49.x release. `§D-005` keeps Tokio; the trigger is a measured
reactor problem the capability model cannot solve.

Naming the trigger is what turns "we chose X" into a position that can be
defended, tested and revised rather than merely inherited.

## Enforcement

| Rule | Enforced by |
|---|---|
| Every decision is cited from the Proposal | `check_xrefs.py` check `[10]` |
| No decision identifier is silently deleted | `check_xrefs.py` check `[10]`, `[11]` |
| Decision identifiers are stable | by convention; they are cited from the Proposal |

Deleting or renumbering a `§D-` entry is a breaking change to the document set,
because the Proposal cites it by number.
