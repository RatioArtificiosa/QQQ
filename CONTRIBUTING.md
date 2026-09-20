# Contributing to QQQ

Thank you for considering it. This document is short on ceremony and specific about expectations.

---

## Read these first

| Document | Why |
|---|---|
| [`PRINCIPLES.md`](PRINCIPLES.md) | The eight non-negotiables. Every change is checked against them. |
| [`QQQ-Proposal-V1.md`](QQQ-Proposal-V1.md) | What we are building and why. |
| [`QQQ-Checklist-V1.md`](QQQ-Checklist-V1.md) | The work breakdown. Find the item you are implementing. |
| [`QQQ-Observations-and-Memories.md`](QQQ-Observations-and-Memories.md) | Decisions already made, and mistakes already made. **Read this before proposing a change to something that looks wrong — it may have been deliberate.** |

---

## The workflow

0. **Configure line endings first.** One command, and without it your working
   tree will drift:

   ```sh
   git config core.autocrlf false
   ```

   This is not optional tidiness. `.gitattributes` pins `eol=lf`, which controls
   what is **committed** — but `core.autocrlf` controls what Git writes to the
   **working tree**, and it does *not* defer to the attribute. With both
   enabled, `git status` reports files modified after a commit that included
   them, with an empty `git diff`, and a dirty tree hides real changes.

   This repository is byte-sensitive — `qqq.lock` carries a covering hash over
   its own bytes and the content store compares digests — so the bytes on disk
   must be the bytes that were committed. A per-repository `git config` cannot
   be committed, which is why it is a setup step rather than a file.
   `python tools/normalize_eol.py --check` runs in CI and will tell you if it is
   wrong.

1. **Find or create a checklist item.** Work that is not on the checklist does not get merged. If your change has no item, add one — with a `→ §x.y` citation to the proposal section it implements.
2. **Open an issue** describing the change, unless it is trivial.
3. **For interface or principle changes, write an RFC** (see below).
4. **Implement** with tests.
5. **Open a pull request** filling in the PR template honestly — including which principle(s) your change touches.

---

## The PR template asks three questions

1. **Which checklist item(s) does this implement or advance?**
2. **Which of the eight principles does this touch, and does it strengthen or weaken them?**
3. **What did you verify, and how?** (A check you ran, not an inspection you performed.)

A PR that cannot answer all three is not ready.

---

## When you need an RFC

Write an RFC in `docs/rfc/` for:

- Any change to [`PRINCIPLES.md`](PRINCIPLES.md)
- Any change to a **published anchor** in the proposal (see the anchor rules below)
- Any breaking change to a published interface (WIT, manifest schema, lockfile, CLI JSON)
- Any new host capability or WIT interface
- Any change to the security model or the capability resolution pipeline

RFCs are discussed publicly for at least seven days before a decision.

---

## Anchor and cross-reference discipline

The proposal and the checklist are bidirectionally linked, and the link is **machine-verified**. Breaking it fails CI.

```bash
python tools/check_xrefs.py
```

**Rules:**

1. Proposal anchors derive from headings and are **stable forever**. You may reword a heading, but you may not change its anchor. Retired sections are tombstoned, not deleted.
2. Checklist IDs (`AREA-NNN`) are **never reused and never renumbered**. A dropped item becomes `AREA-NNN [DROPPED → AREA-MMM]`.
3. Every checklist item cites exactly one primary proposal section.
4. Every proposal section carrying implementation work cites its checklist items.
5. Fix the validator: if `check_xrefs` fails, the PR does not merge — no exceptions, no overrides.

---

## Code standards

- **Rust:** `cargo fmt`, `cargo clippy -- -D warnings`, `cargo deny check`, `cargo machete`.
- **`unsafe`:** forbidden by default (`#![forbid(unsafe_code)]`). The only exceptions are the three named crates, each requiring a written safety argument and review by a second maintainer.
- **No hidden global state.** No implicit environment reads, no working-directory dependencies.
- **Every public API needs a doc comment and a compiling example.**
- **Every error needs a stable `QQQ-XXXX` code, a cause, and a remediation.**

---

## Stub policy

Stubs are permitted only when there is genuinely nothing to connect them to yet. Every stub needs **both**:

1. An inline marker: `// QQQ-STUB(<CHECKLIST-ID>): <reason>`
2. An entry in `QQQ-Observations-and-Memories.md` under §6

A `TODO` without a checklist ID is not permitted. CI enforces the pairing.

---

## Security

**Do not open a public issue for a security vulnerability.** See [`SECURITY.md`](SECURITY.md).

---

## Commit messages

Conventional Commits. Reference the checklist item:

```
feat(cap): implement grant narrowing invariant

Implements CAP-010. Proves no overlay can widen a declared grant.

Refs: §6.2 Capability engine
```

Signed commits are required on `main`.

---

## Developer Certificate of Origin

Every commit must carry a `Signed-off-by` line certifying the
[Developer Certificate of Origin v1.1](https://developercertificate.org/):

```
Signed-off-by: Your Name <you@example.com>
```

Use `git commit -s` (or `-sS` to sign cryptographically as well). The
certification is that you wrote the contribution, or have the right to submit it
under this project's licence — nothing more. It is not a copyright assignment,
and you keep your copyright.

**Why a DCO and not a CLA.** A Contributor Licence Agreement asks contributors to
grant rights they may not realise they are granting, and it is the single most
common reason a first-time contributor does not send a second patch. The DCO
asks for the narrowest thing that makes the contribution legally usable, and it
is what NN-8's stewardship commitment can be kept with.

The check runs in CI. Where it is absent — a merge commit, a revert — the
maintainer records why in the pull request.

---

## Code of conduct

See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Be decent. Technical disagreement is welcome; contempt is not.

---

<p align="center"><sub>Questions? Open a Discussion.</sub></p>
