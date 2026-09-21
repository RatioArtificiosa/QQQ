# Anchor and identifier discipline

Implements Checklist `DOC-008`, expanding Proposal §0.5. These rules are **enforced by
`tools/check_xrefs.py`**, not by review — prose does not fail a build.

The purpose is narrow and worth stating: an anchor is a **link target that other
documents point at**. If it moves, every citation to it breaks silently, and the
breakage appears in a *different* document from the one that caused it. Everything
below follows from making that impossible.

---

## 1. Proposal anchors

### Derivation

An anchor comes from a heading, GitHub-flavoured, with the section number included:

```
## §6.4 Capability Engine   →   #64-capability-engine
```

The algorithm, exactly:

1. Drop the leading `#` characters and surrounding whitespace.
2. Remove `§`.
3. Lowercase.
4. Remove every character that is not alphanumeric, a space, a hyphen or an
   underscore.
5. Replace runs of spaces with a single hyphen.

Note step 4's consequence: the `.` in `§6.4` is **removed**, not converted, so the
anchor is `64-capability-engine` and not `6-4-capability-engine`. That surprises
people, which is why it is written down rather than left to the tool.

`tools/gen_glossary.py` implements the same derivation, and the two are checked against
each other by the glossary's anchors resolving in the Proposal.

### Stability

**Anchors are stable forever.** A section may be renamed in prose — its *title* can
change — but its anchor never does, because checklist items point at it.

In practice this means the heading's text and its anchor can diverge, and that is
correct. `## §6.4 Capability Engine` may be retitled while the anchor stays
`#64-capability-engine` for as long as a single citation exists.

### Retirement

**If a section is retired, its anchor is tombstoned, not deleted.** The heading remains:

```markdown
## §6.4 Capability Engine (retired — see §6.5)
```

so old links resolve to a sentence that explains where the content went. A deleted
heading turns every inbound link into a 404, and the reader cannot tell whether the
section was removed or the link was always wrong.

---

## 2. Checklist identifiers

### Format

`AREA-NNN` — an uppercase area, a hyphen, and **three zero-padded digits**.

Areas are fixed by [Checklist §1](../QQQ-Checklist-V1.md#1-areas). Examples: `SEC-001`,
`HOST-024`, `DOC-011`.

### Rules

| Rule | Why |
|---|---|
| **Never reused** | An ID identifies one piece of work. Reuse makes a citation ambiguous — and a citation is how a reader finds the work. |
| **Never renumbered** | Renumbering breaks every reference in the Proposal, the Observations, commit messages and issue trackers. There is no upside. |
| **Defined exactly once** | Check `[6]` rejects a duplicate. Two items with one ID means one of them is invisible. |
| **Exactly one primary Proposal citation** | Secondary citations are allowed and use `also §…`. The primary is what `check [4]` requires to exist. |

### Dropping an item

An item that is no longer wanted keeps its ID:

```markdown
- [!] **HOST-017 [DROPPED → HOST-022]** Merged into the pooled-allocator item.
```

The ID survives, so a citation from elsewhere still resolves and still explains itself.
Deleting the line would leave the Proposal citing a checklist ID that does not exist —
which is check `[2]`, and it is a real failure rather than a formality.

### Blocked items

An item that cannot be done is marked `[!]`, with the reason recorded in the
Observations and a statement of what would unblock it.

**Before marking anything blocked, ask `§O-082`'s question:** *"is this blocked on the
item, or on one way of doing it?"* It has dissolved three apparent blocks in this
project — `SEC-017`, `SEC-019` and `SEC-026` all turned out to be blocked on one
implementation route rather than on the work. It did not dissolve the external audits,
which is the point of asking rather than assuming.

---

## 3. Observations identifiers

| Prefix | Kind | Example |
|---|---|---|
| `§D-NNN` | **Decision** — a choice made, with its reasoning | `§D-007` determinism |
| `§O-NNN` | **Observation** — something learned by running it | `§O-085` the inert seccomp filter |
| `§M-NNN` | **Mistake** — what went wrong and how it was fixed | `§M-006` a check that could not fail |
| `§C-NNN` | **Correction** — a fix to a claim in the source corpus | `§C-006` the near-native claim |
| `§Q-NNN` | **Open question** — unanswered, paired with an `OQ-NNN` checklist item | `§Q-012` |
| `§O-0NNx` | **Sub-entry** — a note attached to a parent observation | `§O-059f` |

The pairing between `§Q-NNN` and `OQ-NNN` is checked in both directions (check `[9]`):
a question with no checklist item is one nobody will answer, and a checklist item with
no question is one whose context has been lost.

---

## 4. Stub markers

A stub is marked in code with the checklist ID it belongs to:

```rust
// QQQ-STUB(HOST-017): the pooled allocator path is not wired to the epoch ticker
```

and **mirrored in the Observations document**. Check `[7]` fails when a marker exists
without its counterpart, in either direction.

Two markers, not one, because they serve different readers: the code marker tells
someone editing that file, and the Observations entry tells someone auditing whether
the project is complete. A stub visible in only one place is a stub somebody will
mistake for finished work.

---

## 5. What is checked, and by what

| Rule | Check | Fails when |
|---|---|---|
| A checklist item cites a real Proposal section | `[1]` | the anchor does not exist |
| A Proposal line cites a real checklist ID | `[2]` | the ID is not defined |
| A Proposal anchor is defined twice | `[3]` | two headings derive one anchor |
| A checklist item has a Proposal citation | `[4]` | the `→ §` line is missing |
| A checkable Proposal section has a checklist citation | `[5]` | the `→ **Checklist:**` line is missing |
| A checklist ID is defined once | `[6]` | the ID appears twice |
| A stub marker has its Observations entry | `[7]` | either side is missing |
| Appendix A and the corrections agree | `[8]` | a row has no matching `§C-NNN` |
| `§Q-NNN` and `OQ-NNN` agree | `[9]` | one side is missing |
| A cited decision is defined, and vice versa | `[10]`, `[10b]` | either direction breaks |
| The Observations keep their required sections | `[12]` | a section heading is gone |

`tools/self_test_xrefs.py` deliberately breaks each of these and asserts the validator
notices. A validator that cannot fail manufactures confidence rather than safety —
which is `§M-006`, found by writing that harness.

**Not listed above, and worth knowing:** the observation numbering is `§O-NNN` and
prefix-free, so the Observations are *not* renumbered when one is inserted. A new
observation takes the next free number, even when it logically belongs earlier in the
document. That is deliberate: renumbering would invalidate every existing citation to
make a reading order nicer, which is the wrong trade.
